# Created by Reece Pieri, May 2019.
# v1.01, Added "Scan Hosts" button and network scan functionality. Tidied up code. 3/6/19

from tkinter import *
from tkinter import ttk
import wmi
from keyboard import *
import subprocess
import socket
from netaddr import *
import nmap


class Terminate(object):
    def __init__(self):
        # LOADS ON STARTUP. DISPLAYS GUI. #
        self.window = Tk()
        self.window.title("Terminator")
        frame = Frame(self.window)
        frame.pack()
        self.secretframe = Frame(self.window)
        self.secretframe.pack()

        scanbtn = Button(frame, text="Scan Hosts", command=self.scan_network)
        scanbtn.grid(row=0, column=0, columnspan=3, pady=5)
        hostlbl = Label(frame, text="Enter Host IP:")
        hostlbl.grid(row=1, column=0, padx=5, pady=10)
        self.hostent = Entry(frame, width=15)
        self.hostent.grid(row=1, column=1, padx=5, pady=5)
        self.hostent.bind("<Return>", self.connect_to_host)
        connectbtn = Button(frame, text="Connect", command=self.connect_to_host)
        connectbtn.grid(row=1, column=2, padx=5, pady=5)

        processlbl = Label(frame, text="Select Process:")
        processlbl.grid(row=2, column=0, columnspan=3, pady=5)
        self.processcb = ttk.Combobox(frame, width=25)
        self.processcb.grid(row=3, column=0, columnspan=3, pady=3)
        terminatebtn = Button(frame, text="TERMINATE PROCESS", width=18, font=("Helvetica", 10, "bold"),
                              command=self.terminate_process)
        terminatebtn.grid(row=4, column=0, columnspan=3, pady=10)

        self.hostent.focus_set()
        add_word_listener("P@ssw0r", self.secret_menu, "d")
        self.get_ip_details()

        mainloop()

    def get_ip_details(self):
        # GET OWN IP INFORMATION #
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)

        # GET OWN SUBNET MASK
        proc = subprocess.Popen('ipconfig', stdout=subprocess.PIPE)
        while True:
            line = proc.stdout.readline()
            if ip.encode() in line:
                break
        mask = proc.stdout.readline().rstrip().split(b':')[-1].replace(b' ', b'').decode()

        # CONVERT SUBNET MASK TO PREFIX
        network_prefix = "/" + str(IPAddress(mask).netmask_bits())

        # CREATE NETWORK ID
        self.fullnetwork = str(IPNetwork(ip + network_prefix).network) + network_prefix
        # print("Computer name: " + hostname)
        # print("IP address: " + ip)
        # print("Subnet Mask: " + mask)
        # print("Network: " + self.fullnetwork)

    def scan_network(self):
        print("Scanning network. Please wait.")
        nm = nmap.PortScanner()
        nm.scan(hosts=self.fullnetwork, arguments='-n -sP -PE -PA21,23,80,3389')

        for host in nm.all_hosts():
            try:
                nethost = socket.gethostbyaddr(host)
                connection = wmi.WMI(host)
                c = wmi.WMI(wmi=connection)
                for pc in c.Win32_OperatingSystem():
                    hostip = str(host)
                    pcname = str(nethost[0])
                    version = pc.Caption
                    for process in c.Win32_Process(name='explorer.exe'):
                        owner = process.GetOwner()[2]
                    print(hostip + ", " + pcname + ", " + version + ", USER: " + owner)
            except Exception as e:
                print(host + " NULL")
        print("Scan complete.")

    def connect_to_host(self, event=None):
        if self.hostent.get() == "":
            self.processcb.configure(values="")
            print("Please enter host IP.")
        else:
            try:
                self.process_list = []
                connection = wmi.WMI(str(self.hostent.get()))
                self.c = wmi.WMI(wmi=connection)
                for process in self.c.Win32_Process():
                    self.process_list.append(process.Name)
                self.processcb.configure(values=sorted(self.process_list, key=str.lower))
                print("Connected to host: " + str(self.hostent.get()))
            except Exception as e:
                print("Unable to connect to host.")

    def terminate_process(self):
        for process in self.c.Win32_Process(name=self.processcb.get()):
            selectedprocess = process
            self.process_list.pop(self.process_list.index(self.processcb.get()))
            self.processcb.configure(values=sorted(self.process_list, key=str.lower))
        selectedprocess.Terminate()
        print("Process terminated: " + self.processcb.get())
        self.processcb.set("")

    def secret_menu(self):
        print("Secret menu unlocked.")
        reboot_btn = Button(self.secretframe, text="REBOOT PC", width=13, fg="red", font=("Helvetica", 10, "bold"),
                            command=self.reboot_pc)
        reboot_btn.pack()
        shutdown_btn = Button(self.secretframe, text="SHUTDOWN PC", width=13, fg="red", font=("Helvetica", 10, "bold"),
                              command=self.shutdown_pc)
        shutdown_btn.pack(pady=10)
        self.window.update_idletasks()

    def reboot_pc(self):
        os = self.c.Win32_OperatingSystem(Primary=1)[0]
        os.Reboot()

    def shutdown_pc(self):
        os = self.c.Win32_OperatingSystem(Primary=1)[0]
        os.Shutdown()


Terminate()
