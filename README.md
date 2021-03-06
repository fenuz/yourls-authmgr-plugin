yourls-authmgr-plugin
=====================

This plugin adds role-based access controls (RBAC) to YOURLS. By assigning users to roles like "Editor" and "Contributor" you can limit the changes they are permitted to make.

With access controls enabled, you can safely delegate access to the admin pages.

Installation
---------------
1. Download the latest release of yourls-authmgr-plugin.
2. Copy the plugin folder into your user/plugins folder for YOURLS.
3. Set up the parameters for Authmgr (details below)
4. Activate the plugin with the plugin manager in the admin interface.

Default Roles
------------------
The default roles are set up as follows:

Role               | Capabilities
-------------------|------------------------------------------------------
Administrator      | No limits
ShortAdministrator | Cannot manage plugins
Editor             | Cannot manage plugins
Contributor        | Cannot manage plugins, edit URLS, or delete URLs

Configuration
------------------
Add role assignments to your user/config.php file.

```php
$authmgr_role_assignment = array(
  'administrator' => array(
    'your_username',
  ),
  'shortadministrator' => array(
    'your_very_close_friend',
  ),
  'editor' => array(
    'your_close_friend',
  ),
  'contributor' => array(
    'your_other_friend',
  ),
);
```

You can also designate a range of IP addresses that will automatically be granted all capabilities. By default, all accesses from IPv4 localhost (127.0.0.0/8) are granted full access.

```php
$authmgr_admin_ipranges = array(
  '127.0.0.0/8',
);
```

