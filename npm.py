import subprocess
import paramiko
import inspect
import sys
import ast

class RemoteNPM(object):
    def __init__(self, remote_host, remote_user, remote_password):
        self.remote_host = remote_host
        self.remote_user = remote_user
        self.remote_password = remote_password

    def __get_function_info(self, function_str):
        lines = function_str.split('\n')
        min_indent = min(len(line) - len(line.lstrip()) for line in lines if line.strip())
        function_str_fixed = '\n'.join(line[min_indent:] for line in lines)

        tree = ast.parse(function_str_fixed)

        function_node = tree.body[0]

        if isinstance(function_node, ast.FunctionDef):
            function_name = function_node.name
            parameters = [param.arg for param in function_node.args.args]

            return function_name, parameters

        return None, None

    def run_remote_command(self, function_str, *args, **kwargs):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        function_name, parameters = self.__get_function_info(function_str)

        if "python_version" in kwargs.keys():
            python_version = kwargs["python_version"]
            kwargs.pop("python_version")
        else:
            python_version = "python3"

        if "sudo" in kwargs.keys():
            sudo = kwargs["sudo"]
            kwargs.pop("sudo")
        else:
            sudo = False
        
        if "shell_check" in kwargs.keys():
            shell_check = kwargs["shell_check"]
        else:
            shell_check = True

        parameters_string = ""
        for key, value in kwargs.items():
            if key in parameters:
                if key != "shell_check":
                    parameters_string += ", {}={}".format(key, '"{}"'.format(value) if isinstance(value, str) else value)
                else:
                    parameters_string += ", {}={}".format(key, True)
            else:
                kwargs.pop(key)

        if parameters_string != "":
            parameters_string = parameters_string[2:]
        
        ssh.connect(self.remote_host, username=self.remote_user, password=self.remote_password)

        # Lade die Funktionen auf dem entfernten Rechner.
        with ssh.open_sftp().file("remote_npm.py", "w") as f:
            f.write("""{}
import subprocess
import sys

class Local(object):
                 
{}

# Führe die Funktion auf dem entfernten Rechner aus.
result = Local.{}({})
                    
if result:
    print(result)
""".format("# -*- coding: utf-8 -*-\n" if python_version != "python3" else "", function_str, function_name, parameters_string))
            
        if sudo:
            ssh.exec_command('echo "{}" | sudo chown {}:{} remote_npm.py'.format(self.remote_password, self.remote_user, self.remote_user))

        # Führe die Funktionen auf dem entfernten Rechner aus.
        full_command = "{} remote_npm.py".format('echo "{}" | sudo {}'.format(self.remote_password, python_version) if sudo else python_version)
        stdin, stdout, stderr = ssh.exec_command(full_command)
        stdin.flush()

        result_stdout = stdout.read().decode('utf-8')
        
        if shell_check:
            print(result_stdout)
            return_value = None
        else:
            return_value = str(result_stdout)
        
        #ssh.exec_command("echo {} | rm remote_npm.py".format(self.remote_password) if sudo else "rm remote_npm.py")
        ssh.close()
        return str(return_value)
    
    def access_public(self, package=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.access_public)
        return self.run_remote_command(function_str, package=package, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def access_restricted(self, package=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.access_restricted)
        return self.run_remote_command(function_str, package=package, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def access_grant(self, permission, team, package=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.access_grant)
        return self.run_remote_command(function_str, permission=permission, team=team, package=package, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def access_revoke(self, team, package=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.access_revoke)
        return self.run_remote_command(function_str, team=team, package=package, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def access_2fa_required(self, package=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.access_2fa_required)
        return self.run_remote_command(function_str, package=package, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def access_2fa_not_required(self, package=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.access_2fa_not_required)
        return self.run_remote_command(function_str, package=package, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def access_ls_packages(self, identifier=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.access_ls_packages)
        return self.run_remote_command(function_str, identifier=identifier, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def access_ls_collaborators(self, package=None, user=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.access_ls_collaborators)
        return self.run_remote_command(function_str, package=package, user=user, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def access_edit(self, package=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.access_edit)
        return self.run_remote_command(function_str, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def adduser(self, registry=None, scope=None, always_auth=False, auth_type=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.adduser)
        return self.run_remote_command(function_str, registry=registry, scope=scope, always_auth=always_auth, auth_type=auth_type, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def audit(self, output_format=None, audit_level=None, production=False, only=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.audit)
        return self.run_remote_command(function_str, output_format=output_format, audit_level=audit_level, production=production, only=only, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def audit_fix(self, force=False, package_lock_only=False, dry_run=False, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.audit_fix)
        return self.run_remote_command(function_str, force=force, package_lock_only=package_lock_only, dry_run=dry_run, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def bin(self, global_install=False, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.bin)
        return self.run_remote_command(function_str, global_install=global_install, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def bugs(self, package_name=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.bugs)
        return self.run_remote_command(function_str, package_name=package_name, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def build(self, package_folder=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.build)
        return self.run_remote_command(function_str, package_folder=package_folder, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def cache_add_tarball_file(self, tarball_file, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.cache_add_tarball_file)
        return self.run_remote_command(function_str, tarball_file=tarball_file, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def cache_add_folder(self, folder, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.cache_add_folder)
        return self.run_remote_command(function_str, folder=folder, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def cache_add_tarball_url(self, tarball_url, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.cache_add_tarball_url)
        return self.run_remote_command(function_str, tarball_url=tarball_url, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def cache_add_package(self, name, version, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.cache_add_package)
        return self.run_remote_command(function_str, name=name, version=version, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def cache_clean(self, path=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.cache_clean)
        return self.run_remote_command(function_str, path=path, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def cache_verify(self, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.cache_verify)
        return self.run_remote_command(function_str, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def ci(self, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.ci)
        return self.run_remote_command(function_str, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def config_set(self, key, value, global_install=False, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.config_set)
        return self.run_remote_command(function_str, key=key, value=value, global_install=global_install, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def config_get(self, key, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.config_get)
        return self.run_remote_command(function_str, key=key, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def config_delete(self, key, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.config_delete)
        return self.run_remote_command(function_str, key=key, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def config_list(self, long_format=False, json_output=False, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.config_list)
        return self.run_remote_command(function_str, long_format=long_format, json_output=json_output, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def config_edit(self, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.config_edit)
        return self.run_remote_command(function_str, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def npm_get(self, key, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.npm_get)
        return self.run_remote_command(function_str, key=key, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def npm_set(self, key, value, global_install=False, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.npm_set)
        return self.run_remote_command(function_str, key=key, value=value, global_install=global_install, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def dedupe(self, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.dedupe)
        return self.run_remote_command(function_str, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def ddp(self, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.ddp)
        return self.run_remote_command(function_str, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def deprecate(self, package, version, message, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.deprecate)
        return self.run_remote_command(function_str, package=package, version=version, message=message, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def dist_tag_add(self, package, version, tag, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.dist_tag_add)
        return self.run_remote_command(function_str, package=package, version=version, tag=tag, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def dist_tag_rm(self, package, tag, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.dist_tag_rm)
        return self.run_remote_command(function_str, package=package, tag=tag, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def dist_tag_ls(self, package=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.dist_tag_ls)
        return self.run_remote_command(function_str, package=package, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def docs(self, packages=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.docs)
        return self.run_remote_command(function_str, packages=packages, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def home(self, packages=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.home)
        return self.run_remote_command(function_str, packages=packages, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def doctor(self, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.doctor)
        return self.run_remote_command(function_str, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def edit(self, package, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.edit)
        return self.run_remote_command(function_str, package=package, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def explore(self, package, command_args=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.explore)
        return self.run_remote_command(function_str, package=package, command_args=command_args, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def fund(self, package=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.fund)
        return self.run_remote_command(function_str, package=package, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def npm_help(self, term, terms=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.npm_help)
        return self.run_remote_command(function_str, term=term, terms=terms, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def help_search(self, text, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.help_search)
        return self.run_remote_command(function_str, text=text, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def hook_ls(self, package=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.hook_ls)
        return self.run_remote_command(function_str, package=package, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def hook_add(self, entity, url, secret, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.hook_add)
        return self.run_remote_command(function_str, entity=entity, url=url, secret=secret, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def hook_update(self, hook_id, url, secret=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.hook_update)
        return self.run_remote_command(function_str, hook_id=hook_id, url=url, secret=secret, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def hook_rm(self, hook_id, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.hook_rm)
        return self.run_remote_command(function_str, hook_id=hook_id, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def init(self, force=False, scope=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.init)
        return self.run_remote_command(function_str, force=force, scope=scope, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def init_scope(self, create_scope, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.init_scope)
        return self.run_remote_command(function_str, create_scope=create_scope, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def init_name(self, create_name, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.init_name)
        return self.run_remote_command(function_str, create_name=create_name, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def install(self, package=None, tag=None, version=None, version_range=None, alias=None, git_alias=None,
                git_repo=None, tarball_file=None, tarball_url=None, folder=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.install)
        return self.run_remote_command(function_str, package=package, tag=tag, version=version, version_range=version_range, alias=alias, git_alias=git_alias,
                                       git_repo=git_repo, tarball_file=tarball_file, tarball_url=tarball_url, folder=folder, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def install_ci_test(self, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.install_ci_test)
        return self.run_remote_command(function_str, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def install_test(self, package=None, tag=None, version=None, version_range=None, tarball_file=None, tarball_url=None, folder=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.install_test)
        return self.run_remote_command(function_str, package=package, tag=tag, version=version, version_range=version_range, tarball_file=tarball_file, tarball_url=tarball_url, folder=folder, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def link(self, package=None, version=None, scope=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.link)
        return self.run_remote_command(function_str, package=package, version=version, scope=scope, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def logout(self, registry=None, scope=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.logout)
        return self.run_remote_command(function_str, registry=registry, scope=scope, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def ls(self, packages=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.ls)
        return self.run_remote_command(function_str, packages=packages, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def org_set(self, orgname, username, role, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.org_set)
        return self.run_remote_command(function_str, orgname=orgname, username=username, role=role, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def org_rm(self, orgname, username, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.org_rm)
        return self.run_remote_command(function_str, orgname=orgname, username=username, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def org_ls(self, orgname, username=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.org_ls)
        return self.run_remote_command(function_str, orgname=orgname, username=username, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def outdated(self, packages=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.outdated)
        return self.run_remote_command(function_str, packages=packages, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def owner_add(self, user, package, scope=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.owner_add)
        return self.run_remote_command(function_str, user=user, package=package, scope=scope, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def owner_rm(self, user, package, scope=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.owner_rm)
        return self.run_remote_command(function_str, user=user, package=package, scope=scope, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def owner_ls(self, package, scope=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.owner_ls)
        return self.run_remote_command(function_str, package=package, scope=scope, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def pack(self, packages=None, dry_run=False, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.pack)
        return self.run_remote_command(function_str, packages=packages, dry_run=dry_run, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def ping(self, registry=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.ping)
        return self.run_remote_command(function_str, registry=registry, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def prefix(self, global_install=False, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.prefix)
        return self.run_remote_command(function_str, global_install=global_install, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def profile_get(self, parseable=False, json_output=False, property=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.profile_get)
        return self.run_remote_command(function_str, parseable=parseable, json_output=json_output, property=property, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def profile_set(self, property, value, parseable=False, json_output=False, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.profile_set)
        return self.run_remote_command(function_str, property=property, value=value, parseable=parseable, json_output=json_output, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def profile_set_word(self, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.profile_set_word)
        return self.run_remote_command(function_str, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def profile_enable_2fa(self, mode=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.profile_enable_2fa)
        return self.run_remote_command(function_str, mode=mode, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def profile_disable_2fa(self, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.profile_disable_2fa)
        return self.run_remote_command(function_str, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def prune(self, packages=None, production=False, dry_run=False, json_output=False, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.prune)
        return self.run_remote_command(function_str, packages=packages, production=production, dry_run=dry_run, json_output=json_output, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def publish(self, tarball_or_folder=None, tag=None, access=None, otp=None, dry_run=False, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.publish)
        return self.run_remote_command(function_str, tarball_or_folder=tarball_or_folder, tag=tag, access=access, otp=otp, dry_run=dry_run, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def rebuild(self, scopes_and_names=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.rebuild)
        return self.run_remote_command(function_str, scopes_and_names=scopes_and_names, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def repo(self, package=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.repo)
        return self.run_remote_command(function_str, package=package, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def restart(self, remote_args=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.restart).replace("args", "remote_args")
        return self.run_remote_command(function_str, remote_args=remote_args, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def root(self, global_install=False, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.root)
        return self.run_remote_command(function_str, global_install=global_install, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def run_script(self, command, silent=False, remote_args=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.run_script).replace("args", "remote_args")
        return self.run_remote_command(function_str, command=command, silent=silent, remote_args=remote_args, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def search(self, search_terms=None, long_format=False, json_output=False, parseable=False, no_description=False, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.search)
        return self.run_remote_command(function_str, search_terms=search_terms, long_format=long_format, json_output=json_output, parseable=parseable, no_description=no_description, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def shrinkwrap(self, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.shrinkwrap)
        return self.run_remote_command(function_str, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def star(self, packages=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.star)
        return self.run_remote_command(function_str, packages=packages, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def unstar(self, packages=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.unstar)
        return self.run_remote_command(function_str, packages=packages, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def stars(self, user=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.stars)
        return self.run_remote_command(function_str, user=user, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def start(self, remote_args=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.start).replace("args", "remote_args")
        return self.run_remote_command(function_str, remote_args=remote_args, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def stop(self, remote_args=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.stop).replace("args", "remote_args")
        return self.run_remote_command(function_str, remote_args=remote_args, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def team_create(self, scope_team, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.team_create)
        return self.run_remote_command(function_str, scope_team=scope_team, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def team_destroy(self, scope_team, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.team_destroy)
        return self.run_remote_command(function_str, scope_team=scope_team, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def team_add(self, scope_team, user, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.team_add)
        return self.run_remote_command(function_str, scope_team=scope_team, user=user, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def team_rm(self, scope_team, user, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.team_rm)
        return self.run_remote_command(function_str, scope_team=scope_team, user=user, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def team_ls(self, scope_team=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.team_ls)
        return self.run_remote_command(function_str, scope_team=scope_team, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def team_edit(self, scope_team, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.team_edit)
        return self.run_remote_command(function_str, scope_team=scope_team, shell_check=shell_check, working_directory=working_directory, *args, **kwargs)

    def test(self, remote_args=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.test).replace("args", "remote_args")
        return self.run_remote_command(function_str, remote_args=remote_args, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def token_list(self, json_output=False, parseable=False, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.token_list)
        return self.run_remote_command(function_str, json_output=json_output, parseable=parseable, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def token_create(self, read_only=False, cidr=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.token_create)
        return self.run_remote_command(function_str, read_only=read_only, cidr=cidr, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def token_revoke(self, id_or_token, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.token_revoke)
        return self.run_remote_command(function_str, id_or_token=id_or_token, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def uninstall(self, packages, save=False, save_dev=False, save_optional=False, no_save=False, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.uninstall)
        return self.run_remote_command(function_str, packages=packages, save=save, save_dev=save_dev, save_optional=save_optional, no_save=no_save, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def unpublish(self, package, version=None, force=False, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.unpublish)
        return self.run_remote_command(function_str, package=package, version=version, force=force, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def update(self, packages=None, global_install=False, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.update)
        return self.run_remote_command(function_str, packages=packages, global_install=global_install, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def version(self, new_version=None, release_type=None, preid=None, from_git=False, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.version)
        return self.run_remote_command(function_str, new_version=new_version, release_type=release_type, preid=preid, from_git=from_git, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def view(self, package, version=None, field=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.view)
        return self.run_remote_command(function_str, package=package, version=version, field=field, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 
        
    def whoami(self, registry=None, shell_check=True, working_directory=".", *args, **kwargs):
        function_str = inspect.getsource(NPM.whoami)
        return self.run_remote_command(function_str, registry=registry, shell_check=shell_check, working_directory=working_directory, *args, **kwargs) 

class NPM(object):
    @staticmethod
    def access_public(package=None, shell_check=True, working_directory="."):
        command = ['npm', 'access', 'public']
        if package:
            command.append(package)
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def access_restricted(package=None, shell_check=True, working_directory="."):
        command = ['npm', 'access', 'restricted']
        if package:
            command.append(package)
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def access_grant(permission, team, package=None, shell_check=True, working_directory="."):
        command = ['npm', 'access', 'grant', permission, team]
        if package:
            command.append(package)
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def access_revoke(team, package=None, shell_check=True, working_directory="."):
        command = ['npm', 'access', 'revoke', team]
        if package:
            command.append(package)
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def access_2fa_required(package=None, shell_check=True, working_directory="."):
        command = ['npm', 'access', '2fa-required']
        if package:
            command.append(package)
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def access_2fa_not_required(package=None, shell_check=True, working_directory="."):
        command = ['npm', 'access', '2fa-not-required']
        if package:
            command.append(package)
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def access_ls_packages(identifier=None, shell_check=True, working_directory="."):
        command = ['npm', 'access', 'ls-packages']
        if identifier:
            command.append(identifier)
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def access_ls_collaborators(package=None, user=None, shell_check=True, working_directory="."):
        command = ['npm', 'access', 'ls-collaborators']
        if package:
            command.append(package)
        if user:
            command.append(user)
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def access_edit(package=None, shell_check=True, working_directory="."):
        command = ['npm', 'access', 'edit']
        if package:
            command.append(package)
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def adduser(registry=None, scope=None, always_auth=False, auth_type=None, shell_check=True, working_directory="."):
        command = ['npm', 'adduser']
        
        if registry:
            command.extend(['--registry', registry])
        if scope:
            command.extend(['--scope', scope])
        if always_auth:
            command.append('--always-auth')
        if auth_type:
            command.extend(['--auth-type', auth_type])

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def audit(output_format=None, audit_level=None, production=False, only=None, shell_check=True, working_directory="."):
        command = ['npm', 'audit']

        if output_format:
            command.append('--{}'.format(output_format))
        if audit_level:
            command.extend(['--audit-level', audit_level])
        if production:
            command.append('--production')
        if only:
            command.extend(['--only', only])

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def audit_fix(force=False, package_lock_only=False, dry_run=False, shell_check=True, working_directory="."):
        command = ['npm', 'audit', 'fix']

        if force:
            command.append('--force')
        if package_lock_only:
            command.append('--package-lock-only')
        if dry_run:
            command.append('--dry-run')

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def bin(global_install=False, shell_check=True, working_directory="."):
        command = ['npm', 'bin']
        if global_install:
            command.append('-g')

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def bugs(package_name=None, shell_check=True, working_directory="."):
        command = ['npm', 'bugs']
        if package_name:
            command.append(package_name)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def build(package_folder=None, shell_check=True, working_directory="."):
        command = ['npm', 'build']
        if package_folder:
            command.append(package_folder)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def cache_add_tarball_file(tarball_file, shell_check=True, working_directory="."):
        command = ['npm', 'cache', 'add', tarball_file]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def cache_add_folder(folder, shell_check=True, working_directory="."):
        command = ['npm', 'cache', 'add', folder]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def cache_add_tarball_url(tarball_url, shell_check=True, working_directory="."):
        command = ['npm', 'cache', 'add', tarball_url]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def cache_add_package(name, version, shell_check=True, working_directory="."):
        command = ['npm', 'cache', 'add', '{}@{}'.format(name, version)]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def cache_clean(path=None, shell_check=True, working_directory="."):
        command = ['npm', 'cache', 'clean']
        if path:
            command.append(path)
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def cache_verify(shell_check=True, working_directory="."):
        command = ['npm', 'cache', 'verify']
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def ci(shell_check=True, working_directory="."):
        command = ['npm', 'ci']
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def config_set(key, value, global_install=False, shell_check=True, working_directory="."):
        command = ['npm', 'config', 'set', key, value]
        if global_install:
            command.append('-g')
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def config_get(key, shell_check=True, working_directory="."):
        command = ['npm', 'config', 'get', key]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def config_delete(key, shell_check=True, working_directory="."):
        command = ['npm', 'config', 'delete', key]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def config_list(long_format=False, json_output=False, shell_check=True, working_directory="."):
        command = ['npm', 'config', 'list']
        if long_format:
            command.append('-l')
        if json_output:
            command.append('--json')
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def config_edit(shell_check=True, working_directory="."):
        command = ['npm', 'config', 'edit']
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def npm_get(key, shell_check=True, working_directory="."):
        command = ['npm', 'get', key]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def npm_set(key, value, global_install=False, shell_check=True, working_directory="."):
        command = ['npm', 'set', key, value]
        if global_install:
            command.append('-g')
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def dedupe(shell_check=True, working_directory="."):
        command = ['npm', 'dedupe']
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def ddp(shell_check=True, working_directory="."):
        command = ['npm', 'ddp']
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def deprecate(package, version, message, shell_check=True, working_directory="."):
        command = ['npm', 'deprecate', '{}@{}'.format(package, version), message]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def dist_tag_add(package, version, tag, shell_check=True, working_directory="."):
        command = ['npm', 'dist-tag', 'add', '{}@{}'.format(package, version), tag]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def dist_tag_rm(package, tag, shell_check=True, working_directory="."):
        command = ['npm', 'dist-tag', 'rm', package, tag]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def dist_tag_ls(package=None, shell_check=True, working_directory="."):
        command = ['npm', 'dist-tag', 'ls']
        if package:
            command.append(package)
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def docs(packages=None, shell_check=True, working_directory="."):
        command = ['npm', 'docs']
        if packages:
            command.extend(packages)
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def home(packages=None, shell_check=True, working_directory="."):
        command = ['npm', 'home']
        if packages:
            command.extend(packages)
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def doctor(shell_check=True, working_directory="."):
        command = ['npm', 'doctor']
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def edit(package, shell_check=True, working_directory="."):
        command = ['npm', 'edit', package]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def explore(package, command_args=None, shell_check=True, working_directory="."):
        command = ['npm', 'explore', package]
        if command_args:
            command.append('--')
            command.extend(command_args)
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def fund(package=None, shell_check=True, working_directory="."):
        command = ['npm', 'fund']
        if package:
            command.append(package)
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def npm_help(term, terms=None, shell_check=True, working_directory="."):
        command = ['npm', 'help', term]
        if terms:
            command.extend(terms)
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def help_search(text, shell_check=True, working_directory="."):
        command = ['npm', 'help-search', text]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def hook_ls(package=None, shell_check=True, working_directory="."):
        command = ['npm', 'hook', 'ls']
        if package:
            command.append(package)
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def hook_add(entity, url, secret, shell_check=True, working_directory="."):
        command = ['npm', 'hook', 'add', entity, url, secret]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def hook_update(hook_id, url, secret=None, shell_check=True, working_directory="."):
        command = ['npm', 'hook', 'update', hook_id, url]
        if secret:
            command.append(secret)
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def hook_rm(hook_id, shell_check=True, working_directory="."):
        command = ['npm', 'hook', 'rm', hook_id]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def init(force=False, scope=None, shell_check=True, working_directory="."):
        command = ['npm', 'init']
        if force:
            command.append('--force')
        if scope:
            command.extend(['--scope', scope])
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def init_scope(create_scope, shell_check=True, working_directory="."):
        command = ['npx', '{}/create'.format(create_scope)]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def init_name(create_name, shell_check=True, working_directory="."):
        command = ['npx', 'create-{}'.format(create_name)]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def install(package=None, tag=None, version=None, version_range=None, alias=None, git_alias=None,
                git_repo=None, tarball_file=None, tarball_url=None, folder=None, shell_check=True, working_directory="."):
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

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def install_ci_test(shell_check=True, working_directory="."):
        command = ['npm', 'install-ci-test']
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def install_test(package=None, tag=None, version=None, version_range=None, tarball_file=None, tarball_url=None, folder=None, shell_check=True, working_directory="."):
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

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def link(package=None, version=None, scope=None, shell_check=True, working_directory="."):
        command = ['npm', 'link']

        if package:
            if scope:
                command.append('{}/{}'.format(scope, package))
            else:
                command.append(package)

            if version:
                command.append('@{}'.format(version))

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def logout(registry=None, scope=None, shell_check=True, working_directory="."):
        command = ['npm', 'logout']

        if registry:
            command.extend(['--registry', registry])

        if scope:
            command.extend(['--scope', scope])

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def ls(packages=None, shell_check=True, working_directory="."):
        command = ['npm', 'ls']

        if packages:
            command.extend(packages)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def org_set(orgname, username, role, shell_check=True, working_directory="."):
        command = ['npm', 'org', 'set', orgname, username, role]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def org_rm(orgname, username, shell_check=True, working_directory="."):
        command = ['npm', 'org', 'rm', orgname, username]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def org_ls(orgname, username=None, shell_check=True, working_directory="."):
        command = ['npm', 'org', 'ls', orgname]

        if username:
            command.append(username)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def outdated(packages=None, shell_check=True, working_directory="."):
        command = ['npm', 'outdated']

        if packages:
            command.extend(packages)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def owner_add(user, package, scope=None, shell_check=True, working_directory="."):
        command = ['npm', 'owner', 'add', user]

        if scope:
            command.append('{}/{}'.format(scope, package))
        else:
            command.append(package)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def owner_rm(user, package, scope=None, shell_check=True, working_directory="."):
        command = ['npm', 'owner', 'rm', user]

        if scope:
            command.append('{}/{}'.format(scope, package))
        else:
            command.append(package)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def owner_ls(package, scope=None, shell_check=True, working_directory="."):
        command = ['npm', 'owner', 'ls']

        if scope:
            command.append('{}/{}'.format(scope, package))
        else:
            command.append(package)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def pack(packages=None, dry_run=False, shell_check=True, working_directory="."):
        command = ['npm', 'pack']

        if packages:
            command.extend(packages)

        if dry_run:
            command.append('--dry-run')

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def ping(registry=None, shell_check=True, working_directory="."):
        command = ['npm', 'ping']

        if registry:
            command.extend(['--registry', registry])

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def prefix(global_install=False, shell_check=True, working_directory="."):
        command = ['npm', 'prefix']
        if global_install:
            command.append('-g')
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def profile_get(parseable=False, json_output=False, property=None, shell_check=True, working_directory="."):
        command = ['npm', 'profile', 'get']

        if json_output:
            command.append('--json')
        elif parseable:
            command.append('--parseable')

        if property:
            command.append(property)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def profile_set(property, value, parseable=False, json_output=False, shell_check=True, working_directory="."):
        command = ['npm', 'profile', 'set']

        if json_output:
            command.append('--json')
        elif parseable:
            command.append('--parseable')

        command.extend([property, value])
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def profile_set_password(shell_check=True, working_directory="."):
        command = ['npm', 'profile', 'set', 'password']
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def profile_enable_2fa(mode=None, shell_check=True, working_directory="."):
        command = ['npm', 'profile', 'enable-2fa']

        if mode:
            command.append(mode)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def profile_disable_2fa(shell_check=True, working_directory="."):
        command = ['npm', 'profile', 'disable-2fa']
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def prune(packages=None, production=False, dry_run=False, json_output=False, shell_check=True, working_directory="."):
        command = ['npm', 'prune']

        if packages:
            command.extend(packages)

        if production:
            command.append('--production')

        if dry_run:
            command.append('--dry-run')

        if json_output:
            command.append('--json')

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def publish(tarball_or_folder=None, tag=None, access=None, otp=None, dry_run=False, shell_check=True, working_directory="."):
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

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def rebuild(scopes_and_names=None, shell_check=True, working_directory="."):
        command = ['npm', 'rebuild']

        if scopes_and_names:
            command.extend(scopes_and_names)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def repo(package=None, shell_check=True, working_directory="."):
        command = ['npm', 'repo']

        if package:
            command.append(package)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def restart(args=None, shell_check=True, working_directory="."):
        command = ['npm', 'restart']

        if args:
            command.append('--')
            command.extend(args)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def root(global_install=False, shell_check=True, working_directory="."):
        command = ['npm', 'root']

        if global_install:
            command.append('-g')

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def run_script(command, silent=False, args=None, shell_check=True, working_directory="."):
        command = ['npm', 'run-script', command]

        if silent:
            command.append('--silent')

        if args:
            command.append('--')
            command.extend(args)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def search(search_terms=None, long_format=False, json_output=False, parseable=False, no_description=False, shell_check=True, working_directory="."):
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

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def shrinkwrap(shell_check=True, working_directory="."):
        command = ['npm', 'shrinkwrap']
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def star(packages=None, shell_check=True, working_directory="."):
        command = ['npm', 'star']

        if packages:
            command.extend(packages)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def unstar(packages=None, shell_check=True, working_directory="."):
        command = ['npm', 'unstar']

        if packages:
            command.extend(packages)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def stars(user=None, shell_check=True, working_directory="."):
        command = ['npm', 'stars']

        if user:
            command.append(user)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def start(args=None, shell_check=True, working_directory="."):
        command = ['npm', 'start']

        if args:
            command.append('--')
            command.extend(args)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def stop(args=None, shell_check=True, working_directory="."):
        command = ['npm', 'stop']

        if args:
            command.append('--')
            command.extend(args)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def team_create(scope_team, shell_check=True, working_directory="."):
        command = ['npm', 'team', 'create', scope_team]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def team_destroy(scope_team, shell_check=True, working_directory="."):
        command = ['npm', 'team', 'destroy', scope_team]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def team_add(scope_team, user, shell_check=True, working_directory="."):
        command = ['npm', 'team', 'add', scope_team, user]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def team_rm(scope_team, user, shell_check=True, working_directory="."):
        command = ['npm', 'team', 'rm', scope_team, user]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def team_ls(scope_team=None, shell_check=True, working_directory="."):
        command = ['npm', 'team', 'ls']

        if scope_team:
            command.append(scope_team)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def team_edit(scope_team, shell_check=True, working_directory="."):
        command = ['npm', 'team', 'edit', scope_team]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def test(args=None, shell_check=True, working_directory="."):
        command = ['npm', 'test']

        if args:
            command.append('--')
            command.extend(args)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def token_list(json_output=False, parseable=False, shell_check=True, working_directory="."):
        command = ['npm', 'token', 'list']

        if json_output:
            command.append('--json')
        elif parseable:
            command.append('--parseable')

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def token_create(read_only=False, cidr=None, shell_check=True, working_directory="."):
        command = ['npm', 'token', 'create']

        if read_only:
            command.append('--read-only')

        if cidr:
            command.extend(['--cidr', cidr])

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def token_revoke(id_or_token, shell_check=True, working_directory="."):
        command = ['npm', 'token', 'revoke', id_or_token]
        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def uninstall(packages, save=False, save_dev=False, save_optional=False, no_save=False, shell_check=True, working_directory="."):
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

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def unpublish(package, version=None, force=False, shell_check=True, working_directory="."):
        command = ['npm', 'unpublish']

        if package:
            if version:
                command.append('{}@{}'.format(package, version))
            else:
                command.append(package)

            if force:
                command.append('--force')

            if sys.version_info.major == 3:
                result = subprocess.run(command, check=shell_check, cwd=working_directory)
            elif sys.version_info.major == 2:
                result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def update(packages=None, global_install=False, shell_check=True, working_directory="."):
        command = ['npm', 'update']

        if global_install:
            command.append('-g')

        if packages:
            command.extend(packages)

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def version(new_version=None, release_type=None, preid=None, from_git=False, shell_check=True, working_directory="."):
        command = ['npm', 'version']

        if new_version:
            command.append(new_version)
        elif release_type:
            command.append(release_type)

            if preid:
                command.extend(['--preid', preid])

        if from_git:
            command.append('from-git')

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def view(package, version=None, field=None, shell_check=True, working_directory="."):
        command = ['npm', 'view']

        if package:
            if version:
                command.append('{}@{}'.format(package, version))
            else:
                command.append(package)

            if field:
                command.append(field)

            if sys.version_info.major == 3:
                result = subprocess.run(command, check=shell_check, cwd=working_directory)
            elif sys.version_info.major == 2:
                result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None

    @staticmethod
    def whoami(registry=None, shell_check=True, working_directory="."):
        command = ['npm', 'whoami']

        if registry:
            command.extend(['--registry', registry])

        if sys.version_info.major == 3:
            result = subprocess.run(command, check=shell_check, cwd=working_directory)
        elif sys.version_info.major == 2:
            result = subprocess.call(command, shell=shell_check, cwd=working_directory)

        return result.stdout.decode('utf-8') if not shell_check else None
