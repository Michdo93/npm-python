import subprocess
import paramiko
import inspect

class RemoteNPMCommands(object):
    def __init__(self, remote_host, remote_user, remote_password):
        self.remote_host = remote_host
        self.remote_user = remote_user
        self.remote_password = remote_password

    def run_remote_command(self, command):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        ssh.connect(self.remote_host, username=self.remote_user, password=self.remote_password)

        # Lade die Funktionen auf dem entfernten Rechner.
        functions_code = inspect.getsource(RemoteNPMCommands)
        with ssh.open_sftp().file("remote_npm_commands.py", "w") as f:
            f.write(functions_code)

        # Führe die Funktionen auf dem entfernten Rechner aus.
        stdin, stdout, stderr = ssh.exec_command("python remote_npm_commands.py {}".format(command))
        stdin.flush()
        print(stdout.read().decode('utf-8'))
        ssh.close()

class NPM(RemoteNPMCommands):
    @staticmethod
    def access_public(package=None):
        command = ['npm', 'access', 'public']
        if package:
            command.append(package)
        subprocess.run(command, check=True)

    @staticmethod
    def access_restricted(package=None):
        command = ['npm', 'access', 'restricted']
        if package:
            command.append(package)
        subprocess.run(command, check=True)

    @staticmethod
    def access_grant(permission, team, package=None):
        command = ['npm', 'access', 'grant', permission, team]
        if package:
            command.append(package)
        subprocess.run(command, check=True)

    @staticmethod
    def access_revoke(team, package=None):
        command = ['npm', 'access', 'revoke', team]
        if package:
            command.append(package)
        subprocess.run(command, check=True)

    @staticmethod
    def access_2fa_required(package=None):
        command = ['npm', 'access', '2fa-required']
        if package:
            command.append(package)
        subprocess.run(command, check=True)

    @staticmethod
    def access_2fa_not_required(package=None):
        command = ['npm', 'access', '2fa-not-required']
        if package:
            command.append(package)
        subprocess.run(command, check=True)

    @staticmethod
    def access_ls_packages(identifier=None):
        command = ['npm', 'access', 'ls-packages']
        if identifier:
            command.append(identifier)
        subprocess.run(command, check=True)

    @staticmethod
    def access_ls_collaborators(package=None, user=None):
        command = ['npm', 'access', 'ls-collaborators']
        if package:
            command.append(package)
        if user:
            command.append(user)
        subprocess.run(command, check=True)

    @staticmethod
    def access_edit(package=None):
        command = ['npm', 'access', 'edit']
        if package:
            command.append(package)
        subprocess.run(command, check=True)

    @staticmethod
    def adduser(registry=None, scope=None, always_auth=False, auth_type=None):
        command = ['npm', 'adduser']
        
        if registry:
            command.extend(['--registry', registry])
        if scope:
            command.extend(['--scope', scope])
        if always_auth:
            command.append('--always-auth')
        if auth_type:
            command.extend(['--auth-type', auth_type])

        subprocess.run(command, check=True)

    @staticmethod
    def audit(output_format=None, audit_level=None, production=False, only=None):
        command = ['npm', 'audit']

        if output_format:
            command.append(f'--{output_format}')
        if audit_level:
            command.extend(['--audit-level', audit_level])
        if production:
            command.append('--production')
        if only:
            command.extend(['--only', only])

        subprocess.run(command, check=True)

    @staticmethod
    def audit_fix(force=False, package_lock_only=False, dry_run=False):
        command = ['npm', 'audit', 'fix']

        if force:
            command.append('--force')
        if package_lock_only:
            command.append('--package-lock-only')
        if dry_run:
            command.append('--dry-run')

        subprocess.run(command, check=True)

    @staticmethod
    def bin(global_install=False):
        command = ['npm', 'bin']
        if global_install:
            command.append('-g')

        subprocess.run(command, check=True)

    @staticmethod
    def bugs(package_name=None):
        command = ['npm', 'bugs']
        if package_name:
            command.append(package_name)

        subprocess.run(command, check=True)

    @staticmethod
    def build(package_folder=None):
        command = ['npm', 'build']
        if package_folder:
            command.append(package_folder)

        subprocess.run(command, check=True)

    @staticmethod
    def cache_add_tarball_file(tarball_file):
        command = ['npm', 'cache', 'add', tarball_file]
        subprocess.run(command, check=True)

    @staticmethod
    def cache_add_folder(folder):
        command = ['npm', 'cache', 'add', folder]
        subprocess.run(command, check=True)

    @staticmethod
    def cache_add_tarball_url(tarball_url):
        command = ['npm', 'cache', 'add', tarball_url]
        subprocess.run(command, check=True)

    @staticmethod
    def cache_add_package(name, version):
        command = ['npm', 'cache', 'add', f'{name}@{version}']
        subprocess.run(command, check=True)

    @staticmethod
    def cache_clean(path=None):
        command = ['npm', 'cache', 'clean']
        if path:
            command.append(path)
        subprocess.run(command, check=True)

    @staticmethod
    def cache_verify():
        command = ['npm', 'cache', 'verify']
        subprocess.run(command, check=True)

    @staticmethod
    def ci():
        command = ['npm', 'ci']
        subprocess.run(command, check=True)

    @staticmethod
    def config_set(key, value, global_install=False):
        command = ['npm', 'config', 'set', key, value]
        if global_install:
            command.append('-g')
        subprocess.run(command, check=True)

    @staticmethod
    def config_get(key):
        command = ['npm', 'config', 'get', key]
        subprocess.run(command, check=True)

    @staticmethod
    def config_delete(key):
        command = ['npm', 'config', 'delete', key]
        subprocess.run(command, check=True)

    @staticmethod
    def config_list(long_format=False, json_output=False):
        command = ['npm', 'config', 'list']
        if long_format:
            command.append('-l')
        if json_output:
            command.append('--json')
        subprocess.run(command, check=True)

    @staticmethod
    def config_edit():
        command = ['npm', 'config', 'edit']
        subprocess.run(command, check=True)

    @staticmethod
    def npm_get(key):
        command = ['npm', 'get', key]
        subprocess.run(command, check=True)

    @staticmethod
    def npm_set(key, value, global_install=False):
        command = ['npm', 'set', key, value]
        if global_install:
            command.append('-g')
        subprocess.run(command, check=True)

    @staticmethod
    def dedupe():
        command = ['npm', 'dedupe']
        subprocess.run(command, check=True)

    @staticmethod
    def ddp():
        command = ['npm', 'ddp']
        subprocess.run(command, check=True)

    @staticmethod
    def deprecate(package, version, message):
        command = ['npm', 'deprecate', f'{package}@{version}', message]
        subprocess.run(command, check=True)

    @staticmethod
    def dist_tag_add(package, version, tag):
        command = ['npm', 'dist-tag', 'add', f'{package}@{version}', tag]
        subprocess.run(command, check=True)

    @staticmethod
    def dist_tag_rm(package, tag):
        command = ['npm', 'dist-tag', 'rm', package, tag]
        subprocess.run(command, check=True)

    @staticmethod
    def dist_tag_ls(package=None):
        command = ['npm', 'dist-tag', 'ls']
        if package:
            command.append(package)
        subprocess.run(command, check=True)

    @staticmethod
    def docs(packages=None):
        command = ['npm', 'docs']
        if packages:
            command.extend(packages)
        subprocess.run(command, check=True)

    @staticmethod
    def home(packages=None):
        command = ['npm', 'home']
        if packages:
            command.extend(packages)
        subprocess.run(command, check=True)

    @staticmethod
    def doctor():
        command = ['npm', 'doctor']
        subprocess.run(command, check=True)

    @staticmethod
    def edit(package):
        command = ['npm', 'edit', package]
        subprocess.run(command, check=True)

    @staticmethod
    def explore(package, command_args=None):
        command = ['npm', 'explore', package]
        if command_args:
            command.append('--')
            command.extend(command_args)
        subprocess.run(command, check=True)

    @staticmethod
    def fund(package=None):
        command = ['npm', 'fund']
        if package:
            command.append(package)
        subprocess.run(command, check=True)

    @staticmethod
    def npm_help(term, terms=None):
        command = ['npm', 'help', term]
        if terms:
            command.extend(terms)
        subprocess.run(command, check=True)

    @staticmethod
    def help_search(text):
        command = ['npm', 'help-search', text]
        subprocess.run(command, check=True)

    @staticmethod
    def hook_ls(package=None):
        command = ['npm', 'hook', 'ls']
        if package:
            command.append(package)
        subprocess.run(command, check=True)

    @staticmethod
    def hook_add(entity, url, secret):
        command = ['npm', 'hook', 'add', entity, url, secret]
        subprocess.run(command, check=True)

    @staticmethod
    def hook_update(hook_id, url, secret=None):
        command = ['npm', 'hook', 'update', hook_id, url]
        if secret:
            command.append(secret)
        subprocess.run(command, check=True)

    @staticmethod
    def hook_rm(hook_id):
        command = ['npm', 'hook', 'rm', hook_id]
        subprocess.run(command, check=True)

    @staticmethod
    def init(force=False, scope=None):
        command = ['npm', 'init']
        if force:
            command.append('--force')
        if scope:
            command.extend(['--scope', scope])
        subprocess.run(command, check=True)

    @staticmethod
    def init_scope(create_scope):
        command = ['npx', f'{create_scope}/create']
        subprocess.run(command, check=True)

    @staticmethod
    def init_name(create_name):
        command = ['npx', f'create-{create_name}']
        subprocess.run(command, check=True)

    @staticmethod
    def install(package=None, tag=None, version=None, version_range=None, alias=None, git_alias=None,
                git_repo=None, tarball_file=None, tarball_url=None, folder=None):
        command = ['npm', 'install']

        if package:
            command.append(package)
        elif alias:
            command.append(f'{alias}@npm:{package}')
        elif git_alias:
            command.append(f'{git_alias}@{git_repo}')
        elif git_repo:
            command.append(git_repo)
        elif tarball_file:
            command.append(tarball_file)
        elif tarball_url:
            command.append(tarball_url)
        elif folder:
            command.append(folder)

        if tag:
            command.append(f'@{tag}')
        elif version:
            command.append(f'@{version}')
        elif version_range:
            command.append(f'@{version_range}')

        subprocess.run(command, check=True)

    @staticmethod
    def install_ci_test():
        command = ['npm', 'install-ci-test']
        subprocess.run(command, check=True)

    @staticmethod
    def install_test(package=None, tag=None, version=None, version_range=None, tarball_file=None, tarball_url=None, folder=None):
        command = ['npm', 'install-test']

        if package:
            command.append(package)

        if tag:
            command.append(f'@{tag}')
        elif version:
            command.append(f'@{version}')
        elif version_range:
            command.append(f'@{version_range}')

        if tarball_file:
            command.append(tarball_file)
        elif tarball_url:
            command.append(tarball_url)
        elif folder:
            command.append(folder)

        subprocess.run(command, check=True)

    @staticmethod
    def link(package=None, version=None, scope=None):
        command = ['npm', 'link']

        if package:
            if scope:
                command.append(f'{scope}/{package}')
            else:
                command.append(package)

            if version:
                command.append(f'@{version}')

        subprocess.run(command, check=True)

    @staticmethod
    def logout(registry=None, scope=None):
        command = ['npm', 'logout']

        if registry:
            command.extend(['--registry', registry])

        if scope:
            command.extend(['--scope', scope])

        subprocess.run(command, check=True)

    @staticmethod
    def ls(packages=None):
        command = ['npm', 'ls']

        if packages:
            command.extend(packages)

        subprocess.run(command, check=True)

    @staticmethod
    def org_set(orgname, username, role):
        command = ['npm', 'org', 'set', orgname, username, role]
        subprocess.run(command, check=True)

    @staticmethod
    def org_rm(orgname, username):
        command = ['npm', 'org', 'rm', orgname, username]
        subprocess.run(command, check=True)

    @staticmethod
    def org_ls(orgname, username=None):
        command = ['npm', 'org', 'ls', orgname]

        if username:
            command.append(username)

        subprocess.run(command, check=True)

    @staticmethod
    def outdated(packages=None):
        command = ['npm', 'outdated']

        if packages:
            command.extend(packages)

        subprocess.run(command, check=True)

    @staticmethod
    def owner_add(user, package, scope=None):
        command = ['npm', 'owner', 'add', user]

        if scope:
            command.append(f'{scope}/{package}')
        else:
            command.append(package)

        subprocess.run(command, check=True)

    @staticmethod
    def owner_rm(user, package, scope=None):
        command = ['npm', 'owner', 'rm', user]

        if scope:
            command.append(f'{scope}/{package}')
        else:
            command.append(package)

        subprocess.run(command, check=True)

    @staticmethod
    def owner_ls(package, scope=None):
        command = ['npm', 'owner', 'ls']

        if scope:
            command.append(f'{scope}/{package}')
        else:
            command.append(package)

        subprocess.run(command, check=True)

    @staticmethod
    def pack(packages=None, dry_run=False):
        command = ['npm', 'pack']

        if packages:
            command.extend(packages)

        if dry_run:
            command.append('--dry-run')

        subprocess.run(command, check=True)

    @staticmethod
    def ping(registry=None):
        command = ['npm', 'ping']

        if registry:
            command.extend(['--registry', registry])

        subprocess.run(command, check=True)

    @staticmethod
    def prefix(global_install=False):
        command = ['npm', 'prefix']
        if global_install:
            command.append('-g')
        subprocess.run(command, check=True)

    @staticmethod
    def profile_get(parseable=False, json_output=False, property=None):
        command = ['npm', 'profile', 'get']

        if json_output:
            command.append('--json')
        elif parseable:
            command.append('--parseable')

        if property:
            command.append(property)

        subprocess.run(command, check=True)

    @staticmethod
    def profile_set(property, value, parseable=False, json_output=False):
        command = ['npm', 'profile', 'set']

        if json_output:
            command.append('--json')
        elif parseable:
            command.append('--parseable')

        command.extend([property, value])
        subprocess.run(command, check=True)

    @staticmethod
    def profile_set_password():
        command = ['npm', 'profile', 'set', 'password']
        subprocess.run(command, check=True)

    @staticmethod
    def profile_enable_2fa(mode=None):
        command = ['npm', 'profile', 'enable-2fa']

        if mode:
            command.append(mode)

        subprocess.run(command, check=True)

    @staticmethod
    def profile_disable_2fa():
        command = ['npm', 'profile', 'disable-2fa']
        subprocess.run(command, check=True)

    @staticmethod
    def prune(packages=None, production=False, dry_run=False, json_output=False):
        command = ['npm', 'prune']

        if packages:
            command.extend(packages)

        if production:
            command.append('--production')

        if dry_run:
            command.append('--dry-run')

        if json_output:
            command.append('--json')

        subprocess.run(command, check=True)

    @staticmethod
    def publish(tarball_or_folder=None, tag=None, access=None, otp=None, dry_run=False):
        command = ['npm', 'publish']

        if tarball_or_folder:
            command.append(tarball_or_folder)

        if tag:
            command.extend(['--tag', tag])

        if access:
            command.extend(['--access', access])

        if otp:
            command.extend(['--otp', otp])

        if dry_run:
            command.append('--dry-run')

        subprocess.run(command, check=True)

    @staticmethod
    def rebuild(scopes_and_names=None):
        command = ['npm', 'rebuild']

        if scopes_and_names:
            command.extend(scopes_and_names)

        subprocess.run(command, check=True)

    @staticmethod
    def repo(package=None):
        command = ['npm', 'repo']

        if package:
            command.append(package)

        subprocess.run(command, check=True)

    @staticmethod
    def restart(args=None):
        command = ['npm', 'restart']

        if args:
            command.append('--')
            command.extend(args)

        subprocess.run(command, check=True)

    @staticmethod
    def root(global_install=False):
        command = ['npm', 'root']

        if global_install:
            command.append('-g')

        subprocess.run(command, check=True)

    @staticmethod
    def run_script(command, silent=False, args=None):
        npm_command = ['npm', 'run-script', command]

        if silent:
            npm_command.append('--silent')

        if args:
            npm_command.append('--')
            npm_command.extend(args)

        subprocess.run(npm_command, check=True)

    @staticmethod
    def search(search_terms=None, long_format=False, json_output=False, parseable=False, no_description=False):
        command = ['npm', 'search']

        if long_format:
            command.append('--long')

        if json_output:
            command.append('--json')

        if parseable:
            command.append('--parseable')

        if no_description:
            command.append('--no-description')

        if search_terms:
            command.extend(search_terms)

        subprocess.run(command, check=True)

    @staticmethod
    def shrinkwrap():
        command = ['npm', 'shrinkwrap']
        subprocess.run(command, check=True)

    @staticmethod
    def star(packages=None):
        command = ['npm', 'star']

        if packages:
            command.extend(packages)

        subprocess.run(command, check=True)

    @staticmethod
    def unstar(packages=None):
        command = ['npm', 'unstar']

        if packages:
            command.extend(packages)

        subprocess.run(command, check=True)

    @staticmethod
    def stars(user=None):
        command = ['npm', 'stars']

        if user:
            command.append(user)

        subprocess.run(command, check=True)

    @staticmethod
    def start(args=None):
        command = ['npm', 'start']

        if args:
            command.append('--')
            command.extend(args)

        subprocess.run(command, check=True)

    @staticmethod
    def stop(args=None):
        command = ['npm', 'stop']

        if args:
            command.append('--')
            command.extend(args)

        subprocess.run(command, check=True)

    @staticmethod
    def team_create(scope_team):
        command = ['npm', 'team', 'create', scope_team]
        subprocess.run(command, check=True)

    @staticmethod
    def team_destroy(scope_team):
        command = ['npm', 'team', 'destroy', scope_team]
        subprocess.run(command, check=True)

    @staticmethod
    def team_add(scope_team, user):
        command = ['npm', 'team', 'add', scope_team, user]
        subprocess.run(command, check=True)

    @staticmethod
    def team_rm(scope_team, user):
        command = ['npm', 'team', 'rm', scope_team, user]
        subprocess.run(command, check=True)

    @staticmethod
    def team_ls(scope_team=None):
        command = ['npm', 'team', 'ls']

        if scope_team:
            command.append(scope_team)

        subprocess.run(command, check=True)

    @staticmethod
    def team_edit(scope_team):
        command = ['npm', 'team', 'edit', scope_team]
        subprocess.run(command, check=True)

    @staticmethod
    def test(args=None):
        command = ['npm', 'test']

        if args:
            command.append('--')
            command.extend(args)

        subprocess.run(command, check=True)

    @staticmethod
    def token_list(json_output=False, parseable=False):
        command = ['npm', 'token', 'list']

        if json_output:
            command.append('--json')
        elif parseable:
            command.append('--parseable')

        subprocess.run(command, check=True)

    @staticmethod
    def token_create(read_only=False, cidr=None):
        command = ['npm', 'token', 'create']

        if read_only:
            command.append('--read-only')

        if cidr:
            command.extend(['--cidr', cidr])

        subprocess.run(command, check=True)

    @staticmethod
    def token_revoke(id_or_token):
        command = ['npm', 'token', 'revoke', id_or_token]
        subprocess.run(command, check=True)

    @staticmethod
    def uninstall(packages, save=False, save_dev=False, save_optional=False, no_save=False):
        command = ['npm', 'uninstall']

        if packages:
            command.extend(packages)

        if save:
            command.append('-S')
        elif save_dev:
            command.append('-D')
        elif save_optional:
            command.append('-O')
        elif no_save:
            command.append('--no-save')

        subprocess.run(command, check=True)

    @staticmethod
    def unpublish(package, version=None, force=False):
        command = ['npm', 'unpublish']

        if package:
            if version:
                command.append(f'{package}@{version}')
            else:
                command.append(package)

            if force:
                command.append('--force')

            subprocess.run(command, check=True)

    @staticmethod
    def update(packages=None, global_install=False):
        command = ['npm', 'update']

        if global_install:
            command.append('-g')

        if packages:
            command.extend(packages)

        subprocess.run(command, check=True)

    @staticmethod
    def version(new_version=None, release_type=None, preid=None, from_git=False):
        command = ['npm', 'version']

        if new_version:
            command.append(new_version)
        elif release_type:
            command.append(release_type)

            if preid:
                command.extend(['--preid', preid])

        if from_git:
            command.append('from-git')

        subprocess.run(command, check=True)

    @staticmethod
    def view(package, version=None, field=None):
        command = ['npm', 'view']

        if package:
            if version:
                command.append(f'{package}@{version}')
            else:
                command.append(package)

            if field:
                command.append(field)

            subprocess.run(command, check=True)

    @staticmethod
    def whoami(registry=None):
        command = ['npm', 'whoami']

        if registry:
            command.extend(['--registry', registry])

        subprocess.run(command, check=True)
