# npm-python
Use `npm` (node package manager) via `Python`. Optionally also executable via SSH using the `paramiko` module.

## Informations

This code ultimately does nothing other than execute `npm` via `subprocess`. `paramiko` is used for `SSH` so that `npm` can also be executed on external computers using `Python` scripts. However, it is assumed that `npm` is installed on the (target) computers.

Why do we even need a Python wrapper that executes `npm`? It makes it easier to automate `npm` in smart home software such as [Home Assistant](https://www.home-assistant.io/), [openHAB](https://www.openhab.org/) and the like.

## Pre-Installation

This code could be run in `Python 2.7` and `Python 3.x`, so you could choose how to use it. You have to install the `paramiko` module.

For `Python 2.7` you have to run:

```
python -m pip install paramiko
```

For `Python 3.x` you have to run:

```
python3 -m pip install paramiko
```

## Usage

### Import the NPM module

Regardless of whether you are working locally or remotely, you must always import the `NPM` module as follows:

```
from npm import NPM
```

### Output via the terminal

Each function has a `shell_check` parameter which is by default `True`. This means that

```
NPM.start(args=["--port", "3000"])
```

is equivalent to

```
NPM.start(args=["--port", "3000"], shell_check=True)
```

This means that when the Python script is executed, the output of subprocess appears in the command line. There is virtually no difference to when I have entered the corresponding command directly in the command line instead of my Python programme. If you want more complex Python scripts for automation, you want to pass `shell_check=False` to the function and save the return value of the function in a variable. You can of course check this for possible errors or whether everything has worked and can then continue your programme based on this (and possibly execute further npm commands).

### Remote execution (SSH)

To execute `SSH`, `paramiko` is used. SSH` can be executed here for every function. An example looks like this:

```
from npm import RemoteNPM

Remote = RemoteNPM(remote_host='your_remote_host', remote_user='your_username', remote_password='your_password')
Remote.access_public(package='mypackage', shell_check=True)
```

the local equivalent looks like this:

```
NPM.access_public(package='mypackage', shell_check=True)
```

### npm access

Set access level on published packages

```
NPM.access_2fa_required("mypackage")
NPM.access_2fa_not_required("mypackage")
NPM.access_ls_packages("@myorg")
NPM.access_ls_collaborators("mypackage", "myuser")
NPM.access_edit("mypackage")
```

### npm adduser

Add a registry user account

```
NPM.adduser(registry="https://registry.example.com", scope="@myorg", always_auth=True, auth_type="legacy")
```

### npm audit

Run a security audit

```
NPM.audit(output_format="json", audit_level="high", production=True, only="prod")
NPM.audit_fix(force=True, package_lock_only=True, dry_run=True)
```

### npm bin

Display npm bin folder

```
NPM.bin(global_install=True)
```

### npm bugs

Bugs for a package in a web browser maybe

```
NPM.bugs("mypackage")
```

### npm build

Build a package

```
NPM.build("myproject")
```

### npm cache

Manipulates packages cache

```
NPM.cache_add_tarball_file("/path/to/package.tgz")
NPM.cache_add_folder("/path/to/package")
NPM.cache_add_tarball_url("https://example.com/package.tgz")
NPM.cache_add_package("mypackage", "1.0.0")
NPM.cache_clean("/path/to/cache")
NPM.cache_verify()
```

### npm ci

Install a project with a clean slate

```
NPM.ci()
```

### npm completion

Tab completion for npm

```
NPM.source_npm_completion()
```

### npm config

Manage the npm configuration files

```
NPM.config_set("registry", "https://registry.example.com", global_install=True)
NPM.config_get("registry")
NPM.config_delete("registry")
NPM.config_list(long_format=True, json_output=True)
NPM.config_edit()
NPM.npm_get("prefix")
NPM.npm_set("prefix", "/path/to/prefix", global_install=True)
```

### npm dedupe

Reduce duplication

```
NPM.dedupe()
NPM.ddp()
```

### npm deprecate

Deprecate a version of a package

```
NPM.deprecate("mypackage", "1.0.0", "This package is deprecated.")
```

### npm dist-tag

Modify package distribution tags

```
NPM.dist_tag_add("mypackage", "1.0.0", "latest")
NPM.dist_tag_rm("mypackage", "beta")
NPM.dist_tag_ls("mypackage")
```

### npm docs

Docs for a package in a web browser maybe

```
NPM.docs(["mypackage", "anotherpackage"])
NPM.home(["mypackage", "anotherpackage"])
```

### npm doctor

Check your environments

```
NPM.doctor()
```

### npm edit

Edit an installed package

```
NPM.edit("mypackage")
```

### npm explore

Browse an installed package

```
NPM.explore("mypackage", ["--", "ls"])
```

### npm fund

Retrieve funding information

```
NPM.fund("mypackage")
```

### npm help

Search npm help documentation

```
NPM.npm_help("install", ["--save"])
```

### npm help-search

Get help on npm

```
NPM.help_search("npm scripts")
```

### npm hook

Manage registry hooks

```
NPM.hook_ls("mypackage")
NPM.hook_add("myentity", "https://example.com/hook", "mysecret")
NPM.hook_update("123", "https://example.com/newhook", "newsecret")
NPM.hook_rm("456")
```

### npm init

Create a package.json file

```
NPM.init(force=True, scope="@myorg")
NPM.init_scope("@myorg")
NPM.init_name("myproject")
```

### npm install

Install a package

```
NPM.install()
NPM.install("@myorg/mypackage")
NPM.install("mypackage", tag="latest")
NPM.install("mypackage", version="1.0.0")
NPM.install("mypackage", version_range="^1.0.0")
NPM.install(alias="myalias", git_alias="mygitalias", git_repo="https://github.com/user/repo.git")
NPM.install(git_repo="https://github.com/user/repo.git")
NPM.install(tarball_file="/path/to/package.tgz")
NPM.install(tarball_url="https://example.com/package.tgz")
NPM.install(folder="/path/to/package")
```

### npm install-ci-test

Install a project with a clean slate and run tests

```
NPM.install_ci_test()
```

### npm install-test

Install package(s) and run tests

```
NPM.install_test()
NPM.install_test("@myorg/mypackage")
NPM.install_test("mypackage", tag="latest")
NPM.install_test("mypackage", version="1.0.0")
NPM.install_test("mypackage", version_range="^1.0.0")
NPM.install_test(tarball_file="/path/to/package.tgz")
NPM.install_test(tarball_url="https://example.com/package.tgz")
NPM.install_test(folder="/path/to/package")
```

### npm link

Symlink a package folder

```
NPM.link()  # In einem Paketverzeichnis
NPM.link("mypackage")
NPM.link("mypackage", version="1.0.0", scope="@myorg")
```

### npm logout

Log out of the registry

```
NPM.logout(registry="https://example.com", scope="@myorg")
```

### npm ls

List installed packages

```
NPM.ls(["mypackage", "@anotherorg/anotherpackage"])
```

### npm org

Manage orgs

```
NPM.org_set("myorg", "myuser", "developer")
NPM.org_rm("myorg", "myuser")
NPM.org_ls("myorg", "myuser")
```

### npm outdated

Check for outdated packages

```
NPM.outdated(["mypackage", "@anotherorg/anotherpackage"])
```

### npm owner

Manage package owners

```
NPM.owner_add("newowner", "mypackage", scope="@myorg")
NPM.owner_rm("oldowner", "mypackage")
NPM.owner_ls("mypackage", scope="@myorg")
```

### npm pack

Create a tarball from a package

```
NPM.pack(["mypackage", "@anotherorg/anotherpackage"], dry_run=True)
```

### npm ping

Ping npm registry

```
NPM.ping(registry="https://example.com")
```

### npm prefix

Display prefix

```
NPM.prefix(global_install=True)
```

### npm profile

Change settings on your registry profile

```
NPM.profile_get(parseable=True, json_output=True, property="username")
NPM.profile_set("email", "newemail@example.com", json_output=True)
NPM.profile_set_password()
NPM.profile_enable_2fa(mode="auth-and-writes")
NPM.profile_disable_2fa()
```

### npm prune

Remove extraneous packages

```
NPM.prune(["mypackage", "@anotherorg/anotherpackage"], production=True, dry_run=True, json_output=True)
```

### npm publish

Publish a package

```
NPM.publish(tarball_or_folder="mypackage.tgz", tag="beta", access="public", otp="123456", dry_run=True)
```

### npm rebuild

Rebuild a package

```
NPM.rebuild(["@myorg/mypackage"])
```

### npm repo

Open package repository page in the browser

```
NPM.repo("mypackage")
```

### npm restart

Restart a package

```
NPM.restart(["--", "--debug"])
```

### npm root

Display npm root

```
NPM.root(global_install=True)
```

### npm run-script

Run arbitrary package scripts

```
NPM.run_script("build", silent=True, args=["--prod"])
```

### npm search

Search for packages

```
NPM.search(["package-name"], long_format=True, json_output=True, parseable=True)
```

### npm shrinkwrap

Lock down dependency versions for publication

```
NPM.shrinkwrap()
```

### npm star

Mark your favorite packages

```
NPM.star(["mypackage"])
NPM.unstar(["mypackage"])
```

### npm stars

View packages marked as favorites

```
NPM.stars("myuser")
```

### npm start

Start a package

```
NPM.start(args=["--port", "3000"])
```

### npm stop

Stop a package

```
NPM.stop(args=["--port", "3000"])
```

### npm team

Manage organization teams and team memberships

```
NPM.team_create("@myorg:developers")
NPM.team_destroy("@myorg:developers")
NPM.team_add("@myorg:developers", "user123")
NPM.team_rm("@myorg:developers", "user123")
NPM.team_ls("@myorg:developers")
NPM.team_edit("@myorg:developers")
```

### npm test

Test a package

```
NPM.test(args=["--verbose"])
```

### npm token

Manage your authentication tokens

```
NPM.token_list(json_output=True, parseable=True)
NPM.token_create(read_only=True, cidr="1.1.1.1/24,2.2.2.2/16")
NPM.token_revoke("token123")
```

### npm uninstall

Remove a package

```
NPM.uninstall(["mypackage"], save=True)
```

### npm unpublish

Remove a package from the registry

```
NPM.unpublish("mypackage", version="1.0.0", force=True)
```

### npm update

Update a package

```
NPM.update(["mypackage"], global_install=True)
```

### npm version

Bump a package version

```
NPM.version("2.0.0")
```

### npm view

View registry info

```
NPM.view("mypackage", version="1.0.0", field="dependencies")
```

### npm whoami

Display npm username

```
NPM.whoami(registry="https://example.com")
```
