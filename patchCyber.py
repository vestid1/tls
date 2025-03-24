import re
import os.path
import shutil


DEBUG = False


class Logs(object):
    @classmethod
    def debug(cls, text):
        if DEBUG:
            try:
                print('\033[34m[\033[90m~\033[34m] \033[90m%s\033[0m' % str(text))
            except UnicodeEncodeError:
                print('\033[34m[\033[37m~\033[34m] \033[37m%s\033[0m' % str(text))

    @classmethod
    def info(cls, text):
        print('\033[34m[\033[0m*\033[34m] \033[0m%s\033[0m' % str(text))

    @classmethod
    def success(cls, text):
        print('\033[34m[\033[32m+\033[34m] \033[32m%s\033[0m' % str(text))

    @classmethod
    def warn(cls, text):
        print('\033[34m[\033[33m!\033[34m] \033[33m%s\033[0m' % str(text))

    @classmethod
    def error(cls, text):
        print('\033[34m[\033[31mx\033[34m] \033[31m%s\033[0m' % str(text))

    @classmethod
    def crit(cls, text):
        print('\033[34m[\033[35m!\033[34m] \033[35m%s\033[0m' % str(text))

    @classmethod
    def cyan(cls, text):
        print('\033[34m[\033[36m*\033[34m] \033[36m%s\033[0m' % str(text))

    @classmethod
    def vuln(cls, text):
        print('\033[34m[\033[31m!\033[34m] \033[41m\033[37m%s\033[0m' % str(text))


def self_remove():
    if os.path.isfile(__file__):
        os.remove(__file__)


"""
Functions for patching vulnerabilities CVE-2024-51568
"""
def find_filemanager_upload_function(filepath):
    if not os.path.isfile(filepath):
        Logs.error('File %s not found' % filepath)
        return

    with open(filepath, 'r') as fp:
        content = fp.read()

    patern_block_upload_function = re.compile(r'\n(def upload\(request\):)(.*?)\ndef ', re.DOTALL)
    block_upload_function = patern_block_upload_function.search(content)

    if block_upload_function:
        upload_function = block_upload_function.group(2)
        return upload_function
    else:
        Logs.debug('Function "upload" not found in file %s' % filepath)

    return


def is_function_filemanager_upload_vulnerable(block_function):
    patern_vuln = re.compile(r'\n\s+except:[\s\n]+pass[\s\n]+', re.DOTALL)

    if patern_vuln.search(block_function):
        return True

    return False


def patch_filemanager_upload_function(filepath):
    if not os.path.isfile(filepath):
        Logs.error('File %s not found' % filepath)
        return False

    # backup file
    backup_filepath = filepath + '.bak'
    shutil.copy(filepath, backup_filepath)

    with open(filepath, 'r') as fp:
        content = fp.read()

    patern_block_upload_function = re.compile(r'\n(def upload\(request\):)(.*?)\ndef ', re.DOTALL)
    patern_vuln = re.compile(r'(\n\s+except:[\s\n]+)(pass)([\s\n]+)', re.DOTALL)

    block_upload_function = patern_block_upload_function.search(content)

    if block_upload_function:
        upload_function = block_upload_function.group(2)
        patched_upload_function = patern_vuln.sub(r'\1return ACLManager.loadErrorJson()\3', upload_function)
        patched_content = patern_block_upload_function.sub(r'\n\g<1>%s\ndef ' % patched_upload_function, content)
        with open(filepath, 'w') as fp:
            fp.write(patched_content)

        if is_file_filemanager_upload_vulnerable(filepath):
            if DEBUG:
                Logs.error('Failed to patch file %s' % filepath)

            shutil.move(backup_filepath, filepath)
        else:
            if DEBUG:
                Logs.success('Successfully patched file %s' % filepath)

            os.remove(backup_filepath)

            return True

    return False


def is_file_filemanager_upload_vulnerable(filepath):
    block_function = find_filemanager_upload_function(filepath)
    if not block_function:
        return False

    return is_function_filemanager_upload_vulnerable(block_function)


"""
Functions for patching vulnerabilities CVE-2024-51567
"""
def find_databases_upgrade_function(filepath):
    if not os.path.isfile(filepath):
        Logs.error('File %s not found' % filepath)
        return

    with open(filepath, 'r') as fp:
        content = fp.read()

    pattern_block_upgrade_function = re.compile(r'\n(def upgrademysqlstatus\(request\):)(.*?)(\Z|\ndef )', re.DOTALL)
    block_upgrade_function = pattern_block_upgrade_function.search(content)

    if block_upgrade_function:
        upgrade_function = block_upgrade_function.group(1) + block_upgrade_function.group(2)
        return upgrade_function
    else:
        Logs.debug('Function "upgrademysqlstatus" not found in file %s' % filepath)

    return


def is_function_databases_upgrade_vulnerable(block_function):
    pattern_vuln = re.compile(r'\n\s+try:[\s\n]+userID = request.session\[\'userID\'\]', re.DOTALL)

    if not pattern_vuln.search(block_function):
        return True

    return False


def patch_databases_upgrade_function(filepath):
    if not os.path.isfile(filepath):
        Logs.error('File %s not found' % filepath)
        return False

    # Backup file
    backup_filepath = filepath + '.bak'
    shutil.copy(filepath, backup_filepath)

    with open(filepath, 'r') as fp:
        content = fp.read()

    pattern_block_upgrade_function = re.compile(r'\n(def upgrademysqlstatus\(request\):)(.*?)(\Z|\ndef )', re.DOTALL)
    pattern_vuln = re.compile(r'(def upgrademysqlstatus\(request\):([ \t]+)?\n([ \t]+)try:([ \t]+)?\n)([ \t]+)(data = json.loads\(request.body\))', re.DOTALL)

    block_upgrade_function = pattern_block_upgrade_function.search(content)

    if block_upgrade_function:
        upgrade_function = block_upgrade_function.group(1) + block_upgrade_function.group(2)

        block_try = pattern_vuln.search(upgrade_function)

        if not block_try:
            Logs.error('Failed to get block "try"')
            return False

        space_1 = block_try.group(3)
        space_2 = block_try.group(5)

        replaced_upgrade_function = "%suserID = request.session['userID']\n\n" % space_2
        replaced_upgrade_function += "%scurrentACL = ACLManager.loadedACL(userID)\n\n" % space_2
        replaced_upgrade_function += "%sif currentACL['admin'] == 1:\n" % space_2
        replaced_upgrade_function += "%s%spass\n" % (space_2, space_1)
        replaced_upgrade_function += "%selse:\n" % space_2
        replaced_upgrade_function += "%s%sreturn ACLManager.loadErrorJson('FilemanagerAdmin', 0)\n\n" % (space_2, space_1)
        replaced_upgrade_function += "%s" % space_2

        patched_upgrade_function = pattern_vuln.sub(r"\1" + replaced_upgrade_function + r"\6", upgrade_function)
        patched_content = content.replace(upgrade_function, patched_upgrade_function)

        with open(filepath, 'w') as fp:
            fp.write(patched_content)

        if is_file_databases_upgrade_vulnerable(filepath):
            if DEBUG:
                Logs.error('Failed to patch file %s' % filepath)

            shutil.move(backup_filepath, filepath)
        else:
            if DEBUG:
                Logs.success('Successfully patched file %s' % filepath)

            os.remove(backup_filepath)

            return True

    return False


def is_file_databases_upgrade_vulnerable(filepath):
    block_function = find_databases_upgrade_function(filepath)
    if not block_function:
        return False

    return is_function_databases_upgrade_vulnerable(block_function)


"""
Functions for patching vulnerabilities CVE-2024-51378
"""

""" CVE-2024-51378 Part I """
def find_dns_reset_function(filepath):
    if not os.path.isfile(filepath):
        Logs.error('File %s not found' % filepath)
        return

    with open(filepath, 'r') as fp:
        content = fp.read()

    pattern_block_reset_function = re.compile(r'\n(def getresetstatus\(request\):)(.*?)(\Z|\ndef )', re.DOTALL)
    block_reset_function = pattern_block_reset_function.search(content)

    if block_reset_function:
        reset_function = block_reset_function.group(1) + block_reset_function.group(2)
        return reset_function
    else:
        Logs.debug('Function "getresetstatus" not found in file %s' % filepath)
    return


def is_function_dns_reset_vulnerable(block_function):
    pattern_vuln = re.compile(r'\n\s+try:[\s\n]+userID = request.session\[\'userID\'\]', re.DOTALL)

    if not pattern_vuln.search(block_function):
        return True

    return False


def patch_dns_reset_function(filepath):
    if not os.path.isfile(filepath):
        Logs.error('File %s not found' % filepath)
        return False

    # Backup file
    backup_filepath = filepath + '.bak'
    shutil.copy(filepath, backup_filepath)

    with open(filepath, 'r') as fp:
        content = fp.read()

    pattern_block_reset_function = re.compile(r'\n(def getresetstatus\(request\):)(.*?)(\Z|\ndef )', re.DOTALL)
    pattern_vuln = re.compile(r'(def getresetstatus\(request\):([ \t]+)?\n([ \t]+)try:([ \t]+)?\n)([ \t]+)(data = json.loads\(request.body\))', re.DOTALL)

    block_reset_function = pattern_block_reset_function.search(content)

    if block_reset_function:
        reset_function = block_reset_function.group(1) + block_reset_function.group(2)

        block_try = pattern_vuln.search(reset_function)

        if not block_try:
            Logs.error('Failed to get block "try"')
            return False

        space_1 = block_try.group(3)
        space_2 = block_try.group(5)

        replaced_reset_function = "%suserID = request.session['userID']\n\n" % space_2
        replaced_reset_function += "%scurrentACL = ACLManager.loadedACL(userID)\n\n" % space_2
        replaced_reset_function += "%sif currentACL['admin'] == 1:\n" % space_2
        replaced_reset_function += "%s%spass\n" % (space_2, space_1)
        replaced_reset_function += "%selse:\n" % space_2
        replaced_reset_function += "%s%sreturn ACLManager.loadErrorJson('FilemanagerAdmin', 0)\n\n" % (space_2, space_1)
        replaced_reset_function += "%s" % space_2

        patched_reset_function = pattern_vuln.sub(r"\1" + replaced_reset_function + r"\6", reset_function)
        patched_content = content.replace(reset_function, patched_reset_function)

        with open(filepath, 'w') as fp:
            fp.write(patched_content)

        if is_file_dns_reset_vulnerable(filepath):
            if DEBUG:
                Logs.error('Failed to patch file %s' % filepath)

            shutil.move(backup_filepath, filepath)
        else:
            if DEBUG:
                Logs.success('Successfully patched file %s' % filepath)

            os.remove(backup_filepath)

            return True

    return False


def is_file_dns_reset_vulnerable(filepath):
    block_function = find_dns_reset_function(filepath)
    if not block_function:
        return False

    return is_function_dns_reset_vulnerable(block_function)


""" CVE-2024-51378 Part II """
def find_ftp_reset_function(filepath):
    if not os.path.isfile(filepath):
        Logs.error('File %s not found' % filepath)
        return

    with open(filepath, 'r') as fp:
        content = fp.read()

    pattern_block_reset_function = re.compile(r'\n(def getresetstatus\(request\):)(.*?)(\Z|\ndef )', re.DOTALL)
    block_reset_function = pattern_block_reset_function.search(content)

    if block_reset_function:
        reset_function = block_reset_function.group(1) + block_reset_function.group(2)
        return reset_function
    else:
        Logs.debug('Function "getresetstatus" not found in file %s' % filepath)

    return


def is_function_ftp_reset_vulnerable(block_function):
    pattern_vuln = re.compile(r'\n\s+try:[\s\n]+userID = request.session\[\'userID\'\]', re.DOTALL)

    if not pattern_vuln.search(block_function):
        return True

    return False


def patch_ftp_reset_function(filepath):
    if not os.path.isfile(filepath):
        Logs.error('File %s not found' % filepath)
        return False

    # Backup file
    backup_filepath = filepath + '.bak'
    shutil.copy(filepath, backup_filepath)

    with open(filepath, 'r') as fp:
        content = fp.read()

    pattern_block_reset_function = re.compile(r'\n(def getresetstatus\(request\):)(.*?)(\Z|\ndef )', re.DOTALL)
    pattern_vuln = re.compile(r'(def getresetstatus\(request\):([ \t]+)?\n([ \t]+)try:([ \t]+)?\n)([ \t]+)(data = json.loads\(request.body\))', re.DOTALL)

    block_reset_function = pattern_block_reset_function.search(content)

    if block_reset_function:
        reset_function = block_reset_function.group(1) + block_reset_function.group(2)

        block_try = pattern_vuln.search(reset_function)

        if not block_try:
            Logs.error('Failed to get block "try"')
            return False

        space_1 = block_try.group(3)
        space_2 = block_try.group(5)

        replaced_reset_function = "%suserID = request.session['userID']\n\n" % space_2
        replaced_reset_function += "%scurrentACL = ACLManager.loadedACL(userID)\n\n" % space_2
        replaced_reset_function += "%sif currentACL['admin'] == 1:\n" % space_2
        replaced_reset_function += "%s%spass\n" % (space_2, space_1)
        replaced_reset_function += "%selse:\n" % space_2
        replaced_reset_function += "%s%sreturn ACLManager.loadErrorJson('FilemanagerAdmin', 0)\n\n" % (space_2, space_1)
        replaced_reset_function += "%s" % space_2

        patched_reset_function = pattern_vuln.sub(r"\1" + replaced_reset_function + r"\6", reset_function)
        patched_content = content.replace(reset_function, patched_reset_function)

        with open(filepath, 'w') as fp:
            fp.write(patched_content)

        if is_file_ftp_reset_vulnerable(filepath):
            if DEBUG:
                Logs.error('Failed to patch file %s' % filepath)

            shutil.move(backup_filepath, filepath)
        else:
            if DEBUG:
                Logs.success('Successfully patched file %s' % filepath)

            os.remove(backup_filepath)

            return True

    return False


def is_file_ftp_reset_vulnerable(filepath):
    block_function = find_ftp_reset_function(filepath)
    if not block_function:
        return False

    return is_function_ftp_reset_vulnerable(block_function)


""" Check and patch CVE-2024-51568 """
def patch_cve_2024_51568():
    cve = 'CVE-2024-51568'
    cve_light = '\033[0m \033[47m\033[30m %s ' % cve
    filemanager_views = '/usr/local/CyberCP/filemanager/views.py'
    restart_lscpd = False

    Logs.info('Trying check vulnerability %s' % cve_light)

    if is_file_filemanager_upload_vulnerable(filemanager_views):
        Logs.vuln('This target is vulnerable')
        Logs.debug('File: %s is vulnerable' % filemanager_views)

        if patch_filemanager_upload_function(filemanager_views):
            Logs.success('Successfully patched vulnerability')

            restart_lscpd = True
    else:
        Logs.debug('File: %s is not vulnerable' % filemanager_views)
        Logs.cyan('This target is not vulnerable')

    return restart_lscpd


""" Check and patch CVE-2024-51567 """
def patch_cve_2024_51567():
    cve = 'CVE-2024-51567'
    cve_light = '\033[0m \033[47m\033[30m %s ' % cve
    file_databases_views = '/usr/local/CyberCP/databases/views.py'
    restart_lscpd = False

    Logs.info('Trying check vulnerability %s' % cve_light)

    if is_file_databases_upgrade_vulnerable(file_databases_views):
        Logs.vuln('This target is vulnerable')
        Logs.debug('File: %s is vulnerable' % file_databases_views)

        if patch_databases_upgrade_function(file_databases_views):
            Logs.success('Successfully patched vulnerability')

            restart_lscpd = True
    else:
        Logs.debug('File: %s is not vulnerable' % file_databases_views)
        Logs.cyan('This target is not vulnerable')

    return restart_lscpd


""" Check and patch CVE-2024-51378 """
def patch_cve_2024_51378():
    cve = 'CVE-2024-51378'
    cve_light = '\033[0m \033[47m\033[30m %s ' % cve
    file_dns_views = '/usr/local/CyberCP/dns/views.py'
    file_ftp_views = '/usr/local/CyberCP/ftp/views.py'
    vulnerable = False
    restart_lscpd = False

    Logs.info('Trying check vulnerability %s' % cve_light)

    if is_file_dns_reset_vulnerable(file_dns_views):
        vulnerable = True
        Logs.vuln('This target is vulnerable (i)')
        Logs.debug('File: %s is vulnerable' % file_dns_views)

        if patch_dns_reset_function(file_dns_views):
            Logs.success('Successfully patched vulnerability (i)')
            restart_lscpd = True
        else:
            restart_lscpd = False
    else:
        Logs.debug('File: %s is not vulnerable' % file_dns_views)

    if is_file_ftp_reset_vulnerable(file_ftp_views):
        vulnerable = True
        Logs.vuln('This target is vulnerable (ii)')
        Logs.debug('File: %s is vulnerable' % file_ftp_views)

        if patch_ftp_reset_function(file_ftp_views):
            Logs.success('Successfully patched vulnerability (ii)')
            restart_lscpd = True
        else:
            restart_lscpd = False
    else:
        Logs.debug('File: %s is not vulnerable' % file_ftp_views)

    if not vulnerable:
        Logs.cyan('This target is not vulnerable')

    return restart_lscpd


def main():
    restart_lscpd = False

    if patch_cve_2024_51568():
        restart_lscpd = True
    print()

    if patch_cve_2024_51567():
        restart_lscpd = True
    print()

    if patch_cve_2024_51378():
        restart_lscpd = True
    print()

    if restart_lscpd:
        Logs.info('Restarted lscpd')
        os.system('systemctl restart lscpd')

        # Check status of lscpd
        Logs.info('Status of lscpd:')
        os.system('systemctl status lscpd')

    self_remove()


if __name__ == '__main__':
    main()
