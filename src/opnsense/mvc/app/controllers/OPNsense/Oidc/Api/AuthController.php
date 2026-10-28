<?php

namespace OPNsense\Oidc\Api;

use InvalidArgumentException;
use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Auth\OIDC;
use OPNsense\Auth\User;
use OPNsense\Base\ApiControllerBase;
use OPNsense\Base\FieldTypes\ArrayField;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Oidc\OidcClient;
use RuntimeException;

/**
 * Class ServiceController
 * @package OPNsense\Cron
 */
class AuthController extends ApiControllerBase
{
    const ALLOW_USER_CREATION = true;
    const SESSION_AUTH_PROVIDER = 'openid_connect_provider';

    public function doAuth()
    {
        return true;
    }

    public function iconAction()
    {
        $provider = $this->request->get('provider');
        if (empty($provider)) {
            $this->response->setStatusCode(400, "Bad Request");
            return "Missing authentication provider.";
        }

        $auth = (new AuthenticationFactory())->get($provider);
        if ($auth == null || $auth->getType() !== 'oidc') {
            $this->response->setStatusCode(404, "Not Found");
            return "Authentication provider not found.";
        }

        $url = $auth->oidcIconUrl;
        if (empty($url) || !filter_var($url, FILTER_VALIDATE_URL)) {
            $this->response->setStatusCode(404, "Not Found");
            return "Invalid icon URL.";
        }
        // Proxy the image using cURL
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        $imageData = curl_exec($ch);
        $curlErr = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($imageData === false || $httpCode !== 200) {
            $this->response->setStatusCode(404, "Not Found");
            return "Unable to fetch icon. " . ($curlErr ?: "HTTP $httpCode");
        }

        $mimeType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        $this->response->setHeader('Content-Type', $mimeType);
        $this->response->setHeader('Cache-Control', 'public, max-age=31536000, immutable'); // cache for 1 year, aggressive
        return $imageData;
    }

    /**
     * start the authorization code flow
     */
    public function loginAction()
    {
        if ($this->session->get('Username') != null) {
            $this->response->setStatusCode(400, "Bad Request");
            return "Already logged in.";
        }

        // Set the provider in the session
        $provider = $this->request->get('provider');
        if (empty($provider)) {
            $this->response->setStatusCode(400, "Bad Request");
            return "Missing authentication provider.";
        }
        $this->session->set(self::SESSION_AUTH_PROVIDER, $provider);

        // Authenticate
        try {
            $auth = $this->getAuthProvider($provider);
            if ($auth === null)
                return "Authentication provider not found.";
            $user = $this->authenticate($auth);
        } catch (\Exception $e) {
            $this->auditLog(sprintf("OIDC '%s' login request failed: %s", $provider, $e->getMessage()));
            $this->response->setStatusCode(500, "Server Error");
            return "Unable to authenticate, see the system log for details.";
        }

        $this->session->close();
        if ($user === false)
            return 'Redirecting...';

        return "Already logged in but session not setup. Please try again";
    }


    public function callbackAction()
    {
        if ($this->session->get('Username') != null) {
            $this->response->setStatusCode(400, "Bad Request");
            return "Already logged in.";
        }

        // Get the provider from the session
        $provider = $this->session->get(self::SESSION_AUTH_PROVIDER);
        if (empty($provider)) {
            $this->response->setStatusCode(404, "Authentication not found");
            return "Missing authentication provider. Please try the flow again.";
        }
        $this->session->remove(self::SESSION_AUTH_PROVIDER);

        // Check the OIDC flow
        $auth = $this->getAuthProvider($provider);
        if ($auth === null)
            return "Authentication provider not found. Please try the flow again.";

        try {
            $user = $this->authenticate($auth);
            if ($user === false) {
                $this->response->setStatusCode(400, "Authentication not found");
                return "Something went wrong while trying to login you in";
            }
        } catch (\Exception $e) {
            $this->session->close();
            $this->auditLog(sprintf("OIDC '%s' authentication error from %s: %s", $provider, $this->remoteAddress(), $e->getMessage()));
            $this->response->setStatusCode(500, "Server Error");
            return "Unable to authenticate, see the system log for details.";
        }

        $lookupUsername = isset($user->{$auth->oidcUsernameClaim}) ? (string)$user->{$auth->oidcUsernameClaim} : null;
        $lookupEmail    = $auth->oidcMatchEmail && isset($user->email) ? (string)$user->email : null;

        // Restrict to a single Entra ID tenant when configured
        if (!empty($auth->oidcAllowedTenant) && strcasecmp((string)($user->tid ?? ''), trim($auth->oidcAllowedTenant)) !== 0) {
            return $this->deny($provider, $lookupUsername, 'tenant not allowed');
        }

        // Resolve local groups from the role/group claim
        $mappedGroups = $auth->resolveMappedGroups($user);
        if ($auth->oidcRequireGroup && empty($mappedGroups)) {
            return $this->deny($provider, $lookupUsername, 'no mapped group in claim ' . $auth->oidcGroupClaim);
        }

        // Lookup existing local user
        $localUser = $this->findLocalUser($lookupUsername, $lookupEmail);
        if ($localUser === false) {
            if (!self::ALLOW_USER_CREATION || !$auth->oidcCreateUsers) {
                return $this->deny($provider, $lookupUsername, 'no matching local account and user creation disabled');
            }

            // Create the user if allowed
            $localUser = $this->createLocalUser($lookupUsername, $user->email ?? null, $user->name ?? '');
            if ($localUser === false) {
                $this->response->setStatusCode(500, "User creation failed");
                return "Unable to create local account.";
            }

            $initialGroups = array_merge($auth->oidcDefaultGroups, $mappedGroups ?? []);
            $this->syncGroups((string)$localUser->name, $initialGroups, []);
        } elseif ($auth->oidcGroupSync && $mappedGroups !== null) {
            $this->syncGroups((string)$localUser->name, $mappedGroups, $auth->getManagedGroups());
        }

        $localUser = $this->findLocalUser((string)$localUser->name, null);
        if ($localUser === false || !empty((string)$localUser->disabled)) {
            return $this->deny($provider, $lookupUsername, 'local account disabled');
        }

        // Create the main login session and log the user in.
        $username = (string)$localUser->name;
        $cnf = Config::getInstance()->object();
        $this->session->set('Username', strval($username));
        $this->session->set('last_access', time());
        $this->session->set('protocol', strval($cnf->system->webgui->protocol));
        $this->session->set('oidc_user', json_decode(json_encode($user), true));
        $this->session->close();

        // Prevent session fixation, same as the core login flow
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
            session_regenerate_id(true);
            session_write_close();
        }

        $this->auditLog(sprintf("Successful login for user '%s' from: %s (OIDC '%s')", $username, $this->remoteAddress(), $provider), LOG_NOTICE);
        $this->response->redirect('/');
        return 'Redirecting home...';
    }

    /** Logs and rejects a login attempt. */
    protected function deny($provider, $username, $reason)
    {
        // Persist the consumed state/nonce so the flow cannot be replayed
        $this->session->close();
        $this->auditLog(sprintf(
            "Web GUI authentication error for '%s' from %s (OIDC '%s'): %s",
            $username ?? '(unknown)',
            $this->remoteAddress(),
            $provider,
            $reason
        ));
        $this->response->setStatusCode(403, "Forbidden");
        return "Access denied, contact your administrator.";
    }

    /** Writes to the audit log, same facility as the core authentication. */
    protected function auditLog($message, $priority = LOG_ERR)
    {
        openlog('audit', LOG_ODELAY, LOG_AUTH);
        syslog($priority, $message);
        closelog();
    }

    protected function remoteAddress()
    {
        return $_SERVER['REMOTE_ADDR'] ?? '(unknown)';
    }

    protected function getAuthProvider($provider): OIDC|null
    {
        $auth = (new AuthenticationFactory())->get($provider);
        if ($auth == null || $auth->getType() !== 'oidc') {
            $this->response->setStatusCode(404, "Authentication not found");
            return null;
        }
        return $auth;
    }

    protected function authenticate($auth)
    {
        /** @var OIDC $auth */
        $client = new OidcClient($auth, $this);
        $client->addScope($auth->oidcScopes);

        if (!$client->authenticate())
            return false;

        // Claims from the verified ID token (signature, issuer, audience, nonce and expiry checked)
        $claims = $client->getVerifiedClaims();
        if (!is_object($claims))
            return false;

        if ($auth->oidcUseUserInfo) {
            $userInfo = $client->requestUserInfo();
            if (is_object($userInfo)) {
                // UserInfo only fills in claims missing from the ID token
                foreach (get_object_vars($userInfo) as $name => $value) {
                    if (!property_exists($claims, $name)) {
                        $claims->$name = $value;
                    }
                }
            }
        }
        return $claims;
    }

    /** Finds the local user that best matches the given username or email. */
    protected function findLocalUser($username, $email)
    {
        $cnf = Config::getInstance()->object();
        if (empty($cnf->system) || empty($cnf->system->user)) {
            return false;
        }

        foreach ($cnf->system->user as $user) {
            if (($username && (string)$user->name === $username) ||
                ($email && isset($user->email) && (string)$user->email === $email)
            ) {
                return $user;
            }
        }

        return false;
    }


    /** Creates a new local user. */
    protected function createLocalUser($username, $email, $displayName = '')
    {
        if (!self::ALLOW_USER_CREATION)
            return false;

        if (empty($username))
            return false;

        // Create the user using a Model
        $mdl = new User();

        /** @var ArrayField $users */
        $users = $mdl->user;
        $user = $users->add();
        $user->name     = $username;
        $user->email    = $email ?? '';
        $user->descr    = !empty($displayName) ? $displayName : $username;
        $user->comment  = "Created with OpenID Connect";
        // Unusable random password, local login stays impossible until an admin sets one
        $user->password = bin2hex(random_bytes(32));
        $user->scrambled_password = "1";
        $user->scope    = "user";
        $user->disabled = "0";

        if (!$mdl->serializeToConfig())
            return false;

        Config::getInstance()->save();
        (new Backend())->configdpRun('auth sync user', [$username]);

        Config::getInstance()->forceReload();
        return $this->findLocalUser($username, null);
    }

    /**
     * Synchronizes local group memberships.
     * @param string $username local user name
     * @param array $targetGroups groups the user must be a member of
     * @param array $managedGroups groups the user is removed from when not in $targetGroups
     */
    protected function syncGroups($username, $targetGroups, $managedGroups)
    {
        $target  = array_map('strtolower', $targetGroups);
        $managed = array_map('strtolower', $managedGroups);
        if (empty($target) && empty($managed))
            return;

        $localUser = $this->findLocalUser($username, null);
        if ($localUser === false)
            return;
        $uid = (string)$localUser->uid;

        $changed = false;
        $cnf = Config::getInstance()->object();
        foreach ($cnf->system->group as $group) {
            $groupName = strtolower((string)$group->name);
            $wanted = in_array($groupName, $target);
            if (!$wanted && !in_array($groupName, $managed))
                continue;

            $members = [];
            foreach ($group->member as $member) {
                $members = array_merge($members, explode(',', (string)$member));
            }
            $members = array_values(array_filter($members, fn($m) => $m !== ''));
            $isMember = in_array($uid, $members);

            if ($wanted && !$isMember) {
                $members[] = $uid;
                $action = 'link';
            } elseif (!$wanted && $isMember) {
                $members = array_values(array_diff($members, [$uid]));
                $action = 'unlink';
            } else {
                continue;
            }

            syslog(LOG_NOTICE, sprintf('User: policy change for %s %s group %s', $username, $action, (string)$group->name));
            unset($group->member);
            if (!empty($members)) {
                $group->member = implode(',', $members);
            }
            $changed = true;
        }

        if ($changed) {
            Config::getInstance()->save();
            (new Backend())->configdpRun("auth user changed", [$username]);
            Config::getInstance()->forceReload();
        }
    }
}
