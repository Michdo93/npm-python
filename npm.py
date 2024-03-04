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
    def access_public(package=None, check=True):
        command = ['npm', 'access', 'public']
        if package:
            command.append(package)
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def access_restricted(package=None, check=True):
        command = ['npm', 'access', 'restricted']
        if package:
            command.append(package)
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def access_grant(permission, team, package=None, check=True):
        command = ['npm', 'access', 'grant', permission, team]
        if package:
            command.append(package)
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def access_revoke(team, package=None, check=True):
        command = ['npm', 'access', 'revoke', team]
        if package:
            command.append(package)
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def access_2fa_required(package=None, check=True):
        command = ['npm', 'access', '2fa-required']
        if package:
            command.append(package)
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def access_2fa_not_required(package=None, check=True):
        command = ['npm', 'access', '2fa-not-required']
        if package:
            command.append(package)
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def access_ls_packages(identifier=None, check=True):
        command = ['npm', 'access', 'ls-packages']
        if identifier:
            command.append(identifier)
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def access_ls_collaborators(package=None, user=None, check=True):
        command = ['npm', 'access', 'ls-collaborators']
        if package:
            command.append(package)
        if user:
            command.append(user)
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def access_edit(package=None, check=True):
        command = ['npm', 'access', 'edit']
        if package:
            command.append(package)
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def adduser(registry=None, scope=None, always_auth=False, auth_type=None, check=True):
        command = ['npm', 'adduser']
        
        if registry:
            command.extend(['--registry', registry])
        if scope:
            command.extend(['--scope', scope])
        if always_auth:
            command.append('--always-auth')
        if auth_type:
            command.extend(['--auth-type', auth_type])

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def audit(output_format=None, audit_level=None, production=False, only=None, check=True):
        command = ['npm', 'audit']

        if output_format:
            command.append('--{}'.format(output_format))
        if audit_level:
            command.extend(['--audit-level', audit_level])
        if production:
            command.append('--production')
        if only:
            command.extend(['--only', only])

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def audit_fix(force=False, package_lock_only=False, dry_run=False, check=True):
        command = ['npm', 'audit', 'fix']

        if force:
            command.append('--force')
        if package_lock_only:
            command.append('--package-lock-only')
        if dry_run:
            command.append('--dry-run')

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def bin(global_install=False, check=True):
        command = ['npm', 'bin']
        if global_install:
            command.append('-g')

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def bugs(package_name=None, check=True):
        command = ['npm', 'bugs']
        if package_name:
            command.append(package_name)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def build(package_folder=None, check=True):
        command = ['npm', 'build']
        if package_folder:
            command.append(package_folder)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def cache_add_tarball_file(tarball_file, check=True):
        command = ['npm', 'cache', 'add', tarball_file]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def cache_add_folder(folder, check=True):
        command = ['npm', 'cache', 'add', folder]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def cache_add_tarball_url(tarball_url, check=True):
        command = ['npm', 'cache', 'add', tarball_url]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def cache_add_package(name, version, check=True):
        command = ['npm', 'cache', 'add', '{}@{}'.format(name, version)]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def cache_clean(path=None, check=True):
        command = ['npm', 'cache', 'clean']
        if path:
            command.append(path)
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def cache_verify(check=True):
        command = ['npm', 'cache', 'verify']
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def ci(check=True):
        command = ['npm', 'ci']
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def config_set(key, value, global_install=False, check=True):
        command = ['npm', 'config', 'set', key, value]
        if global_install:
            command.append('-g')
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def config_get(key, check=True):
        command = ['npm', 'config', 'get', key]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def config_delete(key, check=True):
        command = ['npm', 'config', 'delete', key]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def config_list(long_format=False, json_output=False, check=True):
        command = ['npm', 'config', 'list']
        if long_format:
            command.append('-l')
        if json_output:
            command.append('--json')
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def config_edit(check=True):
        command = ['npm', 'config', 'edit']
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def npm_get(key, check=True):
        command = ['npm', 'get', key]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def npm_set(key, value, global_install=False, check=True):
        command = ['npm', 'set', key, value]
        if global_install:
            command.append('-g')
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def dedupe(check=True):
        command = ['npm', 'dedupe']
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def ddp(check=True):
        command = ['npm', 'ddp']
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def deprecate(package, version, message, check=True):
        command = ['npm', 'deprecate', '{}@{}'.format(package, version), message]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def dist_tag_add(package, version, tag, check=True):
        command = ['npm', 'dist-tag', 'add', '{}@{}'.format(package, version), tag]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def dist_tag_rm(package, tag, check=True):
        command = ['npm', 'dist-tag', 'rm', package, tag]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def dist_tag_ls(package=None, check=True):
        command = ['npm', 'dist-tag', 'ls']
        if package:
            command.append(package)
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def docs(packages=None, check=True):
        command = ['npm', 'docs']
        if packages:
            command.extend(packages)
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def home(packages=None, check=True):
        command = ['npm', 'home']
        if packages:
            command.extend(packages)
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def doctor(check=True):
        command = ['npm', 'doctor']
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def edit(package, check=True):
        command = ['npm', 'edit', package]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def explore(package, command_args=None, check=True):
        command = ['npm', 'explore', package]
        if command_args:
            command.append('--')
            command.extend(command_args)
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def fund(package=None, check=True):
        command = ['npm', 'fund']
        if package:
            command.append(package)
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def npm_help(term, terms=None, check=True):
        command = ['npm', 'help', term]
        if terms:
            command.extend(terms)
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def help_search(text, check=True):
        command = ['npm', 'help-search', text]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def hook_ls(package=None, check=True):
        command = ['npm', 'hook', 'ls']
        if package:
            command.append(package)
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def hook_add(entity, url, secret, check=True):
        command = ['npm', 'hook', 'add', entity, url, secret]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def hook_update(hook_id, url, secret=None, check=True):
        command = ['npm', 'hook', 'update', hook_id, url]
        if secret:
            command.append(secret)
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def hook_rm(hook_id, check=True):
        command = ['npm', 'hook', 'rm', hook_id]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def init(force=False, scope=None, check=True):
        command = ['npm', 'init']
        if force:
            command.append('--force')
        if scope:
            command.extend(['--scope', scope])
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def init_scope(create_scope, check=True):
        command = ['npx', '{}/create'.format(create_scope)]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def init_name(create_name, check=True):
        command = ['npx', 'create-{}'.format(create_name)]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def install(package=None, tag=None, version=None, version_range=None, alias=None, git_alias=None,
                git_repo=None, tarball_file=None, tarball_url=None, folder=None, check=True):
        command = ['npm', 'install']

        if package:
            command.append(package)
        elif alias:
            command.append('{}@npm:{}'.format(alias, package))
        elif git_alias:
            command.append('{}@{}'.format(git_alias, git_repo))
        elif git_repo:
            command.append(git_repo)
        elif tarball_file:
            command.append(tarball_file)
        elif tarball_url:
            command.append(tarball_url)
        elif folder:
            command.append(folder)

        if tag:
            command.append('@{}'.format(tag))
        elif version:
            command.append('@{}'.format(version))
        elif version_range:
            command.append('@{}'.format(version_range))

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def install_ci_test(check=True):
        command = ['npm', 'install-ci-test']
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def install_test(package=None, tag=None, version=None, version_range=None, tarball_file=None, tarball_url=None, folder=None, check=True):
        command = ['npm', 'install-test']

        if package:
            command.append(package)

        if tag:
            command.append('@{}'.format(tag))
        elif version:
            command.append('@{}'.format(version))
        elif version_range:
            command.append('@{}'.format(version_range))

        if tarball_file:
            command.append(tarball_file)
        elif tarball_url:
            command.append(tarball_url)
        elif folder:
            command.append(folder)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def link(package=None, version=None, scope=None, check=True):
        command = ['npm', 'link']

        if package:
            if scope:
                command.append('{}/{}'.format(scope, package))
            else:
                command.append(package)

            if version:
                command.append('@{}'.format(version))

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def logout(registry=None, scope=None, check=True):
        command = ['npm', 'logout']

        if registry:
            command.extend(['--registry', registry])

        if scope:
            command.extend(['--scope', scope])

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def ls(packages=None, check=True):
        command = ['npm', 'ls']

        if packages:
            command.extend(packages)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def org_set(orgname, username, role, check=True):
        command = ['npm', 'org', 'set', orgname, username, role]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def org_rm(orgname, username, check=True):
        command = ['npm', 'org', 'rm', orgname, username]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def org_ls(orgname, username=None, check=True):
        command = ['npm', 'org', 'ls', orgname]

        if username:
            command.append(username)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def outdated(packages=None, check=True):
        command = ['npm', 'outdated']

        if packages:
            command.extend(packages)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def owner_add(user, package, scope=None, check=True):
        command = ['npm', 'owner', 'add', user]

        if scope:
            command.append('{}/{}'.format(scope, package))
        else:
            command.append(package)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def owner_rm(user, package, scope=None, check=True):
        command = ['npm', 'owner', 'rm', user]

        if scope:
            command.append('{}/{}'.format(scope, package))
        else:
            command.append(package)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def owner_ls(package, scope=None, check=True):
        command = ['npm', 'owner', 'ls']

        if scope:
            command.append('{}/{}'.format(scope, package))
        else:
            command.append(package)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def pack(packages=None, dry_run=False, check=True):
        command = ['npm', 'pack']

        if packages:
            command.extend(packages)

        if dry_run:
            command.append('--dry-run')

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def ping(registry=None, check=True):
        command = ['npm', 'ping']

        if registry:
            command.extend(['--registry', registry])

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def prefix(global_install=False, check=True):
        command = ['npm', 'prefix']
        if global_install:
            command.append('-g')
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def profile_get(parseable=False, json_output=False, property=None, check=True):
        command = ['npm', 'profile', 'get']

        if json_output:
            command.append('--json')
        elif parseable:
            command.append('--parseable')

        if property:
            command.append(property)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def profile_set(property, value, parseable=False, json_output=False, check=True):
        command = ['npm', 'profile', 'set']

        if json_output:
            command.append('--json')
        elif parseable:
            command.append('--parseable')

        command.extend([property, value])
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def profile_set_password(check=True):
        command = ['npm', 'profile', 'set', 'password']
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def profile_enable_2fa(mode=None, check=True):
        command = ['npm', 'profile', 'enable-2fa']

        if mode:
            command.append(mode)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def profile_disable_2fa(check=True):
        command = ['npm', 'profile', 'disable-2fa']
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def prune(packages=None, production=False, dry_run=False, json_output=False, check=True):
        command = ['npm', 'prune']

        if packages:
            command.extend(packages)

        if production:
            command.append('--production')

        if dry_run:
            command.append('--dry-run')

        if json_output:
            command.append('--json')

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def publish(tarball_or_folder=None, tag=None, access=None, otp=None, dry_run=False, check=True):
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

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def rebuild(scopes_and_names=None, check=True):
        command = ['npm', 'rebuild']

        if scopes_and_names:
            command.extend(scopes_and_names)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def repo(package=None, check=True):
        command = ['npm', 'repo']

        if package:
            command.append(package)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def restart(args=None, check=True):
        command = ['npm', 'restart']

        if args:
            command.append('--')
            command.extend(args)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def root(global_install=False, check=True):
        command = ['npm', 'root']

        if global_install:
            command.append('-g')

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def run_script(command, silent=False, args=None, check=True):
        npm_command = ['npm', 'run-script', command]

        if silent:
            npm_command.append('--silent')

        if args:
            npm_command.append('--')
            npm_command.extend(args)

        result = subprocess.run(npm_command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def search(search_terms=None, long_format=False, json_output=False, parseable=False, no_description=False, check=True):
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

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def shrinkwrap(check=True):
        command = ['npm', 'shrinkwrap']
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def star(packages=None, check=True):
        command = ['npm', 'star']

        if packages:
            command.extend(packages)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def unstar(packages=None, check=True):
        command = ['npm', 'unstar']

        if packages:
            command.extend(packages)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def stars(user=None, check=True):
        command = ['npm', 'stars']

        if user:
            command.append(user)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def start(args=None, check=True):
        command = ['npm', 'start']

        if args:
            command.append('--')
            command.extend(args)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def stop(args=None, check=True):
        command = ['npm', 'stop']

        if args:
            command.append('--')
            command.extend(args)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def team_create(scope_team, check=True):
        command = ['npm', 'team', 'create', scope_team]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def team_destroy(scope_team, check=True):
        command = ['npm', 'team', 'destroy', scope_team]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def team_add(scope_team, user, check=True):
        command = ['npm', 'team', 'add', scope_team, user]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def team_rm(scope_team, user, check=True):
        command = ['npm', 'team', 'rm', scope_team, user]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def team_ls(scope_team=None, check=True):
        command = ['npm', 'team', 'ls']

        if scope_team:
            command.append(scope_team)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def team_edit(scope_team, check=True):
        command = ['npm', 'team', 'edit', scope_team]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def test(args=None, check=True):
        command = ['npm', 'test']

        if args:
            command.append('--')
            command.extend(args)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def token_list(json_output=False, parseable=False, check=True):
        command = ['npm', 'token', 'list']

        if json_output:
            command.append('--json')
        elif parseable:
            command.append('--parseable')

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def token_create(read_only=False, cidr=None, check=True):
        command = ['npm', 'token', 'create']

        if read_only:
            command.append('--read-only')

        if cidr:
            command.extend(['--cidr', cidr])

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def token_revoke(id_or_token, check=True):
        command = ['npm', 'token', 'revoke', id_or_token]
        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def uninstall(packages, save=False, save_dev=False, save_optional=False, no_save=False, check=True):
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

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def unpublish(package, version=None, force=False, check=True):
        command = ['npm', 'unpublish']

        if package:
            if version:
                command.append('{}@{}'.format(package, version))
            else:
                command.append(package)

            if force:
                command.append('--force')

            result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def update(packages=None, global_install=False, check=True):
        command = ['npm', 'update']

        if global_install:
            command.append('-g')

        if packages:
            command.extend(packages)

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def version(new_version=None, release_type=None, preid=None, from_git=False, check=True):
        command = ['npm', 'version']

        if new_version:
            command.append(new_version)
        elif release_type:
            command.append(release_type)

            if preid:
                command.extend(['--preid', preid])

        if from_git:
            command.append('from-git')

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def view(package, version=None, field=None, check=True):
        command = ['npm', 'view']

        if package:
            if version:
                command.append('{}@{}'.format(package, version))
            else:
                command.append(package)

            if field:
                command.append(field)

            result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None

    @staticmethod
    def whoami(registry=None, check=True):
        command = ['npm', 'whoami']

        if registry:
            command.extend(['--registry', registry])

        result = subprocess.run(command, check=check)
        return result.stdout.decode('utf-8') if not check else None
