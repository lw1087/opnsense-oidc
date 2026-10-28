<?php

/*
 * Copyright (C) 2015-2023 Deciso B.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\Auth;

use OPNsense\Core\Config;

/**
 * Class Local user database connector (using legacy xml structure).
 * @package OPNsense\Auth
 */
class OIDC extends Local implements IAuthConnector
{
    public $oidcProviderUrl = null;
    public $oidcClientId = null;
    public $oidcClientSecret = null;
    public $oidcCreateUsers = false;
    public $oidcUsernameClaim = 'preferred_username';
    public $oidcDefaultGroups = [];
    public $oidcScopes = [
        'openid',
        'email',
        'profile',
    ];

    public $oidcAuthorizationEndpoint = null;
    public $oidcTokenEndpoint = null;
    public $oidcUserInfoEndpoint = null;

    public $oidcCustomButton = null;
    public $oidcIconUrl = null;

    // Identity and authorization (Microsoft Entra ID friendly)
    public $oidcRedirectUri = null;
    public $oidcUseUserInfo = false;
    public $oidcMatchEmail = false;
    public $oidcAllowedTenant = null;
    public $oidcGroupClaim = 'roles';
    public $oidcGroupMap = [];
    public $oidcGroupSync = false;
    public $oidcRequireGroup = false;


    /**
     * type name in configuration
     * @return string
     */
    public static function getType()
    {
        return 'oidc';
    }

    /**
     * user friendly description of this authenticator
     * @return string
     */
    public function getDescription()
    {
        return "<i class='fa fa-key-o fa-fw fa-brands fa-openid'></i> " . gettext('OpenID Connect');
    }

    /**
     * set connector properties
     * @param array $config connection properties
     */
    public function setProperties($config)
    {
        $confMap = [
            'oidc_provider_url' => 'oidcProviderUrl',
            'oidc_client_id' => 'oidcClientId',
            'oidc_client_secret' => 'oidcClientSecret',
            'oidc_custom_button' => 'oidcCustomButton',
            'oidc_authorization_endpoint' => 'oidcAuthorizationEndpoint',
            'oidc_token_endpoint' => 'oidcTokenEndpoint',
            'oidc_userinfo_endpoint' => 'oidcUserInfoEndpoint',
            'oidc_icon_url' => 'oidcIconUrl',
            'oidc_create_users' => 'oidcCreateUsers',
            'oidc_username_claim' => 'oidcUsernameClaim',
            'oidc_redirect_uri' => 'oidcRedirectUri',
            'oidc_use_userinfo' => 'oidcUseUserInfo',
            'oidc_match_email' => 'oidcMatchEmail',
            'oidc_allowed_tenant' => 'oidcAllowedTenant',
            'oidc_group_claim' => 'oidcGroupClaim',
            'oidc_group_sync' => 'oidcGroupSync',
            'oidc_require_group' => 'oidcRequireGroup',
        ];

        // >> map properties 1-on-1
        foreach ($confMap as $confSetting => $objectProperty) {
            if (!empty($config[$confSetting]) && property_exists($this, $objectProperty)) {
                $this->$objectProperty = $config[$confSetting];
            }
        }

        $this->oidcDefaultGroups = array_values(array_filter(array_map('trim', explode(',', $config['oidc_default_groups'] ?? ''))));
        if (!empty($config['oidc_scopes'])) {
            $this->oidcScopes = array_values(array_filter(array_map('trim', explode(',', $config['oidc_scopes']))));
        }
        $this->oidcGroupMap = static::parseGroupMap($config['oidc_group_map'] ?? '');
    }

    /**
     * parse "claimValue=localGroup" entries separated by newlines, commas or semicolons
     * @param string $value raw configuration value
     * @return array claim value => list of local group names
     */
    public static function parseGroupMap($value)
    {
        $map = [];
        foreach (preg_split('/[\r\n,;]+/', (string)$value) as $entry) {
            $parts = explode('=', $entry, 2);
            if (count($parts) !== 2) {
                continue;
            }
            $claimValue = trim($parts[0]);
            $localGroup = trim($parts[1]);
            if ($claimValue === '' || $localGroup === '') {
                continue;
            }
            $map[$claimValue][] = $localGroup;
        }
        return $map;
    }

    /**
     * resolve the local groups granted by the values of the configured group claim
     * @param object $claims verified token claims
     * @return array|null list of local group names, null when no mapping is configured
     */
    public function resolveMappedGroups($claims)
    {
        if (empty($this->oidcGroupMap)) {
            return null;
        }

        $claimName = $this->oidcGroupClaim;
        $values = $claims->$claimName ?? [];
        if (!is_array($values)) {
            $values = [$values];
        }

        $groups = [];
        foreach ($values as $value) {
            foreach ($this->oidcGroupMap[(string)$value] ?? [] as $localGroup) {
                $groups[] = $localGroup;
            }
        }
        return array_values(array_unique($groups));
    }

    /**
     * all local groups this authenticator manages through the group map
     * @return array list of local group names
     */
    public function getManagedGroups()
    {
        $groups = [];
        foreach ($this->oidcGroupMap as $localGroups) {
            $groups = array_merge($groups, $localGroups);
        }
        return array_values(array_unique($groups));
    }

    /**
     * retrieve configuration options
     * @return array
     */
    public function getConfigurationOptions()
    {

        $callbackURL = gettext("Set your callback URL to <code>https://{opnsense-ip}/api/oidc/auth/callback</code>.");
        $options = [
            // Configuration
            'oidc_provider_url' => [
                'name' => gettext('Provider URL'),
                'help' => gettext('URL to the OpenID Connect provider. Either the root or the <code>/.well-known/openid-configuration</code> path.') . ' ' . $callbackURL,
                'type' => 'text',
                'validate' => fn($value) => filter_var($value, FILTER_VALIDATE_URL) ? [] : [gettext('Discovery needs a valid URL.')],

            ],
            'oidc_client_id' => [
                'name' => gettext('Client ID'),
                'type' => 'text',
                'validate' => fn($value) => !empty($value) ? [] : [gettext('Client ID must not be empty.')]
            ],
            'oidc_client_secret' => [
                'name' => gettext('Client Secret'),
                'type' => 'text',
                'validate' => fn($value) => !empty($value) ? [] : [gettext('Client Secret must not be empty. "Public Clients" are not supported.')]
            ],
            'oidc_username_claim' => [
                'name' => gettext('Username claim'),
                'help' => gettext('The claim to use as local username. The claim must be provided by the OpenID Connect provider. Usually this is <code>preferred_username</code> or <code>email</code>.'),
                'type' => 'text',
                'validate' => fn($value) => !empty($value) ? [] : [gettext('Username claim must not be empty.')]
            ],
            'oidc_scopes' => [
                'name' => gettext('Scopes'),
                'help' => gettext('Scopes to request during authentication. The <code>openid</code> scope is required.'),
                'type' => 'text',
                'default' => join(',', $this->oidcScopes),
                'validate' => fn($value) => [],
            ],
            'oidc_redirect_uri' => [
                'name' => gettext('Redirect URI'),
                'help' => gettext('Fixed callback URL registered at the provider, e.g. <code>https://fw.example.com/api/oidc/auth/callback</code>. When empty it is derived from the request Host header (not recommended).'),
                'type' => 'text',
                'validate' => fn($value) => empty($value) || filter_var($value, FILTER_VALIDATE_URL) ? [] : [gettext('Redirect URI needs a valid URL.')],
            ],
            'oidc_allowed_tenant' => [
                'name' => gettext('Allowed tenant ID'),
                'help' => gettext('Microsoft Entra ID only: reject tokens whose <code>tid</code> claim differs from this tenant ID.'),
                'type' => 'text',
                'validate' => fn($value) => [],
            ],
            'oidc_use_userinfo' => [
                'name' => gettext('Query UserInfo endpoint'),
                'help' => gettext('Merge claims from the UserInfo endpoint into the ID token claims. Leave disabled for Microsoft Entra ID, its UserInfo endpoint does not return <code>preferred_username</code>, <code>roles</code> or <code>groups</code>.'),
                'type' => 'checkbox',
                'validate' => fn($value) => [],
            ],
            'oidc_match_email' => [
                'name' => gettext('Match users by email'),
                'help' => gettext('Also match local users by the <code>email</code> claim. Only enable when the provider guarantees verified, immutable email addresses.'),
                'type' => 'checkbox',
                'validate' => fn($value) => [],
            ],

            // Authorization
            'oidc_group_claim' => [
                'name' => gettext('Group claim'),
                'help' => gettext('Claim holding the user roles or groups, e.g. <code>roles</code> (Entra app roles) or <code>groups</code>.'),
                'type' => 'text',
                'default' => $this->oidcGroupClaim,
                'validate' => fn($value) => [],
            ],
            'oidc_group_map' => [
                'name' => gettext('Group mapping'),
                'help' => gettext('One <code>claimValue=localGroup</code> per line, e.g. <code>OPNsense.Admin=admins</code>.'),
                'type' => 'text',
                'validate' => function ($value) {
                    foreach (preg_split('/[\r\n,;]+/', (string)$value) as $entry) {
                        if (trim($entry) !== '' && !str_contains($entry, '=')) {
                            return [sprintf(gettext('Invalid group mapping entry "%s".'), htmlspecialchars(trim($entry)))];
                        }
                    }
                    return [];
                },
            ],
            'oidc_group_sync' => [
                'name' => gettext('Synchronize groups'),
                'help' => gettext('On every login add and remove the user from the mapped local groups. Groups not present in the mapping are left untouched.'),
                'type' => 'checkbox',
                'validate' => fn($value) => [],
            ],
            'oidc_require_group' => [
                'name' => gettext('Require mapped group'),
                'help' => gettext('Deny the login when none of the claim values is present in the group mapping.'),
                'type' => 'checkbox',
                'validate' => fn($value) => [],
            ],

            // Advance
            'oidc_create_users' => [
                'name' => gettext('Automatic user creation'),
                'help' => gettext(
                    "To be used in combination with synchronize or default groups, allow the authenticator to create new local users after " .
                        "successful login with group memberships returned for the user."
                ),
                'type' => 'checkbox',
                'validate' => fn($value) => [],
            ],
            'oidc_default_groups' => [
                'name' => gettext('Default groups'),
                'help' => gettext("Group(s) to add by default when creating users"),
                'type' => 'text',
                'default' => join(',', $this->oidcDefaultGroups)
            ],

            // Decorative
            'oidc_icon_url' => [
                'name' => gettext('Icon URL'),
                'help' => gettext('URL to an icon representing the OIDC provider. This should be a small image (16x16 or 32x32) in either PNG or SVG format. This image will be proxied.'),
                'type' => 'text',
                'validate' => fn($value) => empty($value) || filter_var($value, FILTER_VALIDATE_URL) ? [] : [gettext('Icon URL needs a valid URL.')],
            ],
            'oidc_custom_button' => [
                'name' => gettext('Custom Button'),
                'help' => gettext('Custom HTML Button. The templated <code>%name%</code>, <code>%url%</code>, and <code>%icon%</code> are available.'),
                'type' => 'text',
                'validate' => fn($value) => [],
            ],
            '__oidc_script' => [
                'name' => '',
                'help' => "<style>{$this->getConfigurationStyle()}</style><script>{$this->getConfigurationScript()}</script>"
            ]
        ];

        return $options;
    }

    /**
     * unused
     * @return array mixed named list of authentication properties
     */
    public function getLastAuthProperties()
    {
        return [];
    }

    public function preauth($username)
    {
        return false;
    }

    public function authenticate($username, $password)
    {
        return false;
    }

    protected function getConfigurationScript()
    {
        $availableGroups = [];
        foreach (config_read_array('system', 'group') as $group)
            $availableGroups[$group['name']] = $group['name'];
        $availableGroupsJson = json_encode($availableGroups);

        // These are a hack to get the UI to behave. 
        return <<<JS
// Handle custom group selector
$('[name=oidc_default_groups]')
    .attr({ type: 'hidden' })
    .after(
        $('<select>')
            .attr('id', 'oidc_default_groups_select')
            .attr('multiple', true)
            .attr('class', 'selectpicker')
            .on('change', function() {
                const selected = $(this).val() || [];
                $('[name=oidc_default_groups]').val(selected.join(','));
            })
            .append(
                Object.entries($availableGroupsJson).map(([key, value]) =>
                    $('<option>').val(key).text(value).attr({ selected: $('[name=oidc_default_groups]').val().split(',').includes(key) })
                )
            )
    );

// Handle changing field types
$('[name=oidc_custom_button]').attr({ rows: 10 })
$('[name=oidc_group_map]').attr({ rows: 5 })
$('[name=oidc_client_secret]').attr({ type: 'password', autocomplete: 'off' });
$('[name=oidc_custom_button],[name=oidc_group_map]').each((i, elm) => {
    const ta = $('<textarea>');
    $.each(elm.attributes, (_, attr) => ta.attr(attr.name, attr.value));
    ta.data($(elm).data());
    ta.val($(elm).val());
    $(elm).replaceWith(ta);
});

// Test button
$(function() {
    $('#submit').after(
        $('<button>')
        .attr({ class: 'btn btn-primary auth_options auth_oidc', style: 'margin-left: 10px' })
        .text('Test')
        .on('click', async (e) => {
            e.preventDefault();

            const data = {};
            $('[name^=oidc_]').each((i, e) => data[$(e).attr('name')] = $(e).val()); 

            $.ajax({
                type: "POST",
                url: '/api/oidc/discover/available',
                data,
                success: function (data) {
                    if (data.errorMessage) {
                        BootstrapDialog.show({
                            title: 'OpenID Connect Test - Failed',
                            message: data.errorMessage || 'Unknown error has occured.',
                            type: BootstrapDialog.TYPE_DANGER
                        });
                        return;
                    }

                    let claimsHtml = '';
                    let scopesHtml = '';
                    if (data.claims && Object.keys(data.claims).length > 0)
                        claimsHtml = `<h5>Claims</h5><ul><li>\${data.claims.join('</li><li>')}</li></ul>`;
                    if (data.scopes && Object.keys(data.scopes).length > 0)
                        scopesHtml = `<h5>Scopes</h5><ul><li>\${data.scopes.join('</li><li>')}</li></ul>`;
                    
                    BootstrapDialog.show({
                        title: 'OpenID Connect Test - Success',
                        message: 'Successfully connected to the well-known.<br>' + claimsHtml + scopesHtml + "<hr>This does not test the client secret or id.",
                        type: BootstrapDialog.TYPE_SUCCESS
                    });
                },
                error: function(jqXHR) {
                    BootstrapDialog.show({
                        title: 'OpenID Connect Test - Failed',
                        message: jqXHR.responseJSON?.errorMessage || jqXHR.responseText,
                        type: BootstrapDialog.TYPE_DANGER
                    });
                }
            });
        })
    );
});

JS;
    }

    protected function getConfigurationStyle()
    {
        return <<<CSS
        .auth_oidc:has(.oidc-icon) input { 
            float: left;
        }
        .oidc-icon {
            width: 32px;
            height: 32px;
        }
        .auth_oidc:has(#help_for_field_oidc___oidc_script)
         {
            display: none !important;
        }
CSS;
    }
}
