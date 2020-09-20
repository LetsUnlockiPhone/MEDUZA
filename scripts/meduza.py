import sys
import frida
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import NameOID, ExtensionOID
import json


class CertSpoofer:

    NAME = "MEDUZA iOS SSL unpinning tool\nby Dima Kovalenko (@kov4l3nko)"

    HELP = """
    Usage:
        $ python3 meduza.py -l
        to list applications
        
        $ python3 meduza.py -s <app name of id> path/to/frida/script.js
        to spawn an application and generate an SSL (un)pinning Frida script
        
        $ python3 meduza.py -a <app name of id> path/to/frida/script.js
        to attach an application and generate an SSL (un)pinning Frida script
        
        $ python3 meduza.py -s <app name of id> path/to/frida/script.js payload.js
        to spawn an application and generate an SSL (un)pinning Frida script with a specially 
        crafted payload (the payload.js should be placed alongside with the py file)
        
        $ python3 meduza.py -a <app name of id> path/to/frida/script.js payload.js
        to attach an application and generate an SSL (un)pinning Frida script with a specially 
        crafted payload (the payload.js should be placed alongside with the py file)
    """

    CERTS = {}
    DOMAIN_CERTS = {}
    DOMAINS = {}

    @staticmethod
    def print_help_and_exit():
        print(CertSpoofer.HELP)
        exit()

    def list_applications(self, print_result=False):
        print("[*] Waiting for an iOS device connected to USB...")
        self.device = frida.get_usb_device()
        applications = self.device.enumerate_applications()
        if print_result:
            print("[*] A list of installed applications:")
            for app in applications:
                print("\t{} {} ({}){}".format(
                    "-" if app.pid == 0 else "+",
                    app.name,
                    app.identifier,
                    " is running, pid={}".format(app.pid) if app.pid != 0 else "")
                )
        return applications

    def parse_command_line(self):
        if len(sys.argv) == 2 and sys.argv[1] == "-l":
            # List application on the device connected to USB
            self.list_applications(print_result=True)
            exit()
        elif len(sys.argv) > 3:
            # Parse 1st arg
            action = sys.argv[1]
            if action == "-s":
                self.spawn = True
            elif action == "-a":
                self.spawn = False
            else:
                print("[*] Unknown first argument {}".format(sys.argv[1]))
                self.print_help_and_exit()
            # Parse 2nd arg
            app_name_or_id = sys.argv[2]
            applications = self.list_applications()
            found = False
            for app in applications:
                if app.name == app_name_or_id or app.identifier == app_name_or_id:
                    found = True
                    self.app = app
            if not found:
                print("[*] Application {} not found! Use -l to list installed/running apps".format(app_name_or_id))
                CertSpoofer.print_help_and_exit()
            if (not self.spawn) and (self.app.pid == 0):
                print(
                    "[*] {} is not running. Please open the app and try again "
                    "or use -s to spawn the app with the script"
                    .format(app_name_or_id)
                )
                CertSpoofer.print_help_and_exit()
            # Parse 3rd argument
            self.js_output_path = os.path.abspath(os.path.expandvars(os.path.expanduser(sys.argv[3])))
            if os.path.exists(self.js_output_path):
                print(
                    "[*] {} already exists, please specify a non-existing file in already existing directory, "
                    "the file will be created"
                    .format(self.js_output_path)
                )
                exit()
            if not os.path.exists(os.path.dirname(self.js_output_path)):
                print(
                    "[*] The dir {} does not exists, please specify a non-existing file in already existing directory, "
                    "it will be created"
                    .format(self.js_output_path)
                )
                exit()
            # Parse 4rd argument if any
            if len(sys.argv) == 5:
                self.payload = sys.argv[4]
        else:
            print("[*] Wrong command line!")
            CertSpoofer.print_help_and_exit()

    def run_app(self):
        # Get app's pid
        if self.spawn:
            print("[*] Spawning {}...".format(self.app.identifier))
            pid = self.device.spawn([self.app.identifier])
        else:
            pid = self.app.pid
        # Create session
        print("[*] Attaching to {}...".format(self.app.identifier))
        self.session = self.device.attach(pid)
        # Read the JS scripts
        print("[*] Reading JS payload {}...".format(self.payload))
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.payload)
        # Read the JS code
        js_file_handle = open(script_path, "r")
        js_code = js_file_handle.read()
        js_file_handle.close()
        # Create script and load it to the process
        print("[*] Injecting JS payload to the process...")
        script = self.session.create_script(js_code)
        script.on("message", CertSpoofer.on_message)
        script.load()
        # Resume the process, if the script just spawned it
        if self.spawn:
            print("[*] Resuming the application...")
            self.device.resume(pid)

    @staticmethod
    def on_message(message, data):
        # Process the data sent by the script
        if message["type"] == "send":
            payload = message['payload']
            if payload.startswith("["):
                print(payload)
            elif payload not in CertSpoofer.CERTS:
                # Get the certificate
                CertSpoofer.CERTS[payload] = list(data)
                print("[*] Got another certificate, its raw SHA256 hash: {}".format(payload))
                # Parse the certificate, get all the common names
                cert = x509.load_der_x509_certificate(data, default_backend())
                cns = []
                for i in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                    t = i.value
                    # If t does not contain spaces, but it contains dots, it's probably a domain name
                    if (" " not in t) and ("." in t):
                        cns.append(t)
                try:
                    cns += cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
                except:
                    pass
                # Remove duplicates
                cns = list(dict.fromkeys(cns))
                # Add the domain to the list if at least one domain name found
                if len(cns) > 0:
                    CertSpoofer.DOMAIN_CERTS[payload] = CertSpoofer.CERTS[payload]
                # Set domain name/hash pairs
                for domain in cns:
                    CertSpoofer.DOMAINS[domain] = payload
                # Print the name(s)
                if len(cns) > 0:
                    print("\t{}".format("\n\t".join(cns)))
        elif message['type'] == 'error':
            print("[!] Error in the JS payload:")
            print(message['stack'])

    def save_to_js(self):
        print("[*] Saving the result to {}...".format(self.js_output_path))
        # Reading the template
        template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "meduza-template.js")
        f = open(template_path, "r")
        template = f.read()
        f.close()
        # Serialize the data
        domains = json.dumps(CertSpoofer.DOMAINS, indent=4)
        certs = json.dumps(CertSpoofer.DOMAIN_CERTS)
        # Write the result to the file
        f = open(self.js_output_path, "w")
        f.write("/*\n\n\tThe script was autorenerated by MEDUZA SSL unpinning tool (https://github.com/kov4l3nko/MEDUZA)\n\n*/\n\n")
        f.write("var certs = {};\n\n".format(certs))
        f.write("var domains = {};\n\n".format(domains))
        f.write(template)
        f.close()
        print("[*] Done!")

    def __init__(self):
        # Init object fields with their default values
        self.spawn = None
        self.app = None
        self.js_output_path = None
        self.device = None
        self.session = None
        self.payload = "meduza.js"
        # Print name/version
        print("{}\n{}\n".format(CertSpoofer.NAME, "=" * len(CertSpoofer.NAME)))
        # Parse command line
        self.parse_command_line()
        # Run the app with the Frida script
        self.run_app()
        # Wait for complete
        input("[*] Press ENTER to complete (you can do it anytime)...\n")
        self.session.detach()
        # Save results to the file
        self.save_to_js()


CertSpoofer()

