#!/usr/bin/env python
#
# Written by Sammy Shuck
#
# Note: Based on pyvmomi sample code export_vm.py
#
# MUST USE PYTHON 3.5
# Python 3.6 doesn't seem to work right now

# TODO: NEED TO ADD SOME METHODS TO THE ExportVM CLASS TO EXPORT THE .VMX AND .VMSN FILES FROM THE DATASTORE
# TODO: NEDD TO ADD A METHOD TO LinkedClone CLASS TO DELETE CLONE AND REMOVE THE SNAPSHOT
# TODO: NEED TO GET THE LOGGING SETUP PROPERLY. POSSIBLY USING A LOGGER CLASS HOWEVER get_logger() FUNCTION WORKS WELL
# TODO: CLEANUP AND UPDATE SOME CODE AREAS SPECIFICALLY IN THE get_logger() FUNCTION AND THE VirtMachine CLASS

import sys
import os
import ssl
import re
import hashlib
import platform
import threading
import requests
import argparse
import atexit
import logging
import logging.config
import logging.handlers
from time import sleep
from datetime import datetime
from pyVmomi import vim, vmodl
from pyVim import connect, task
from vmwarelogin.credential import CryptoKey, Credential, Encryption


# disable  urllib3 warnings
if hasattr(requests.packages.urllib3, 'disable_warnings'):
    requests.packages.urllib3.disable_warnings()

# Global declarations
LOGGERS = {}


class Args:
    """
    Args Class handles the cmdline arguments passed to the code
    Usage can be stored to a variable or called by Args().<property>
    """
    def __init__(self):
        # Retrieve and set script arguments for use throughout
        parser = argparse.ArgumentParser(description="Deploy a new VM Performance Collector VM.")
        # parser.add_argument('-debug', '--debug',
        #                     required=False, action='store_true',
        #                     help='Used for Debug level information')
        parser.add_argument('-vc', '--vcenter',
                            required=True, action='store',
                            help='vCenter to Connect To')
        parser.add_argument('-d', '--destination',
                            required=True, action='store',
                            help='Local Destination Path to Export')
        parser.add_argument('-v', '--vm',
                            required=True, action='store',
                            help='VM to Export')
        parser.add_argument('-u', '--username', default=None,
                            required=False, action='store',
                            help='Username')
        parser.add_argument('-p', '--password', default=None,
                            required=False, action='store',
                            help='Password')
        args = parser.parse_args()
        self.username = args.username
        self.__password = args.password
        self.vcenter = args.vcenter
        self.vm = args.vm
        self.destination = args.destination

    def get(self):
        return self.__password


class CustomObject(object):
    """ Because I came from powershell I was really spoiled with New-Object PSObject
    So I created a class that acts similar in which I can add and remove properties.

     TODO:
    """

    def __init__(self, property={}):
        for k, v in property.items():
            setattr(self, k, v)

    def add_property(self, property):
        for k, v in property.items():
            setattr(self, k, v)

    def remove_property(self, property_name):
        delattr(self, property_name)


class Vcenter:
    """
    Vcenter class handles basic vcenter methods such as connect, disconnect, get_container_view, ect
    """
    def __init__(self, name, username=None, password=None, credential=None, ssl_context=None):
        self.si = None
        self.content = None
        self.cookies = None
        self.vcenter = name
        self.username = username
        self.__password = password
        self.__credential = credential
        self.ssl_context = ssl_context

    def connect(self):
        """
        validate whether username/password were passed or whether a private key should be used

        logger lines have been commented out until logging is fully implemented
        :return:
        """
        # TODO: Ensure logging is setup properly to reinstate the logger lines
        #logger = get_logger('connect_vcenter')

        try:
            # if no ssl_context has been provided then set this to unverified context
            if not self.ssl_context:
                self.ssl_context = ssl._create_unverified_context()
                self.ssl_context.verify_mode = ssl.CERT_NONE

            #logger.debug('Getting Credential Information')
            if self.__credential and self.__credential is dict:
                self.username = self.__credential.get('username', None)
                self.__password = self.__credential.get('password', None)
            elif self.__credential and not self.__credential is dict:
                raise TypeError("Credential must be type <class 'dict'> not " + str(type(self.__credential)))
            elif not self.__password and not self.__credential:
                #logger.debug('No username or password provided. Will read from encrypted files')
                args = Args()
                #logger.debug('args: {}'.format(args))
                cred = Credential('vCenter')
                # ToDo: change this to use a read-only username oppvfog01
                self.username = 'oppvmwre'
                if platform.system() == 'Windows':
                    self.__password = cred.get(private_key=args['secdir'] + '\\privkey',
                                        encrypted_password=open(args['secdir'] + '\\secure', 'rb').read(),
                                        crypto_path=args['secdir'] + '\\crypto')
                elif platform.system() == 'Linux':
                    self.__password = cred.get(private_key=args['secdir'] + '/privkey',
                                        encrypted_password=open(args['secdir'] + '/secure', 'rb').read(),
                                        crypto_path=args['secdir'] + '/crypto')
            #logger.info('Conecting to vCenter {}'.format(self.vcenter))
            #logger.debug(
            #    'Connection Params: vCenter: {}, Username: {}, {}, SSL_Context: {}'.format(self.vcenter, self.username, self.__password,
            #                                                                               self.ssl_context))
            si = connect.SmartConnect(host=self.vcenter,
                                      user=self.username,
                                      pwd=self.__password,
                                      sslContext=self.ssl_context
                                      )

            atexit.register(connect.Disconnect, si)
            #logger.debug('ServiceInstance: {}'.format(si))

            self.si = si
            self.content = si.RetrieveContent()

        except BaseException as e:
            print('Exception: {} \n Args: {}'.format(e, e.args))
            #logger.exception('Exception: {} \n Args: {}'.format(e, e.args))

    def disconnect(self):
        connect.Disconnect(self.si)

    def get_container_view(self, view_type, search_root=None, filter_expression=None):
        """
        Custom container_view function that allows the option for a filtered expression such as name == john_doe
        This is similar to the Where clause in powershell, however, this is case sensative.
        This function does not handle multiple evaluations such as 'and/or'. This can only evaluate a single expression.
        :param view_type: MoRef type [vim.VirtualMachine] , [vim.HostSystem], [vim.ClusterComputeResource], ect
        :param search_root: ManagedObject to search from, by default this is rootFolder
        :param filter_expression: Only return results that match this expression
        :return: list of ManagedObjects
        """

        def create_filter_spec(pc, obj_view, view_type, prop):
            """
            Creates a Property filter spec for each property in prop
            :param pc:
            :param obj_view:
            :param view_type:
            :param prop:
            :return:
            """

            objSpecs = []

            for obj in obj_view:
                objSpec = vmodl.query.PropertyCollector.ObjectSpec(obj=obj)
                objSpecs.append(objSpec)
            filterSpec = vmodl.query.PropertyCollector.FilterSpec()
            filterSpec.objectSet = objSpecs
            propSet = vmodl.query.PropertyCollector.PropertySpec(all=False)
            propSet.type = view_type[0]
            propSet.pathSet = prop
            filterSpec.propSet = [propSet]
            return filterSpec

        def filter_results(result, value, operator):
            """
            Evaluates the properties based on the operator and the value being searched for.
            This does not accept  multiple evaluations (and, or) such as prop1 == value1 and prop2 == value2
            :param result:
            :param value:
            :param operator:
            :return:
            """

            objs = []

            # value and operator are a list as a preparation for later being able to evaluate and, or statements as well
            #  so for now we will just reference the 0 index since only a single expression can be given at this time
            operator = operator[0]
            value = value[0]
            if operator == '==':
                for o in result:
                    if o.propSet[0].val == value:
                        objs.append(o.obj)
                return objs
            elif operator == '!=':
                for o in result:
                    if o.propSet[0].val != value:
                        objs.append(o.obj)
                return objs
            elif operator == '>':
                for o in result:
                    if o.propSet[0].val > value:
                        objs.append(o.obj)
                return objs
            elif operator == '<':
                for o in result:
                    if o.propSet[0].val < value:
                        objs.append(o.obj)
                return objs
            elif operator == '>=':
                for o in result:
                    if o.propSet[0].val >= value:
                        objs.append(o.obj)
                return objs
            elif operator == '<=':
                for o in result:
                    if o.propSet[0].val <= value:
                        objs.append(o.obj)
                return objs
            elif operator == '-like':
                regex_build = ".*"
                for v in value.split('*'):
                    if v == '"' or v == "'":
                        regex_build = regex_build + ".*"
                    else:
                        tmp = v.strip("'")
                        tmp = tmp.strip('"')
                        regex_build = regex_build + "(" + re.escape(tmp) + ").*"
                regex = re.compile(regex_build)
                for o in result:
                    if regex.search(o.propSet[0].val):
                        objs.append(o.obj)
                return objs
            elif operator == '-notlike':
                regex_build = ".*"
                for v in value.split('*'):
                    if v == '"' or v == "'":
                        regex_build = regex_build + ".*"
                    else:
                        tmp = v.strip("'")
                        tmp = tmp.strip('"')
                        regex_build = regex_build + "(" + re.escape(tmp) + ").*"
                regex = re.compile(regex_build)
                for o in result:
                    if not regex.search(o.propSet[0].val):
                        objs.append(o.obj)
                return objs
            else:
                return None

        def break_down_expression(expression):
            """
            Pass an expression to this function and retrieve 3 things,
            1. the property to be evaluated
            2. the value of the property to be evaluated
            3. the operand of the the expression
            :param expression:
            :return:
            """

            operators = ["==", "!=", ">", "<", ">=", "<=", "-like", "-notlike", "-contains", "-notcontains"]
            expression_obj = CustomObject()
            for op in operators:
                exp_split = None
                exp_split = expression.split(op)
                if type(exp_split) is list and len(exp_split) == 2:
                    exp_obj = CustomObject(property={'prop': exp_split[0].strip(),
                                                     'operator': op,
                                                     'value': exp_split[1].strip()})
                    # expression_obj.add_property(property={'exp': exp_obj})
                    return [exp_obj]

        if not search_root:
            search_root = self.content.rootFolder

        view_reference = self.content.viewManager.CreateContainerView(container=search_root,
                                                                 type=view_type,
                                                                 recursive=True)
        view = view_reference.view
        view_reference.Destroy()

        if filter_expression:

            expression_obj = break_down_expression(filter_expression)

            property_collector = self.content.propertyCollector
            filter_spec = create_filter_spec(property_collector, view, view_type, [obj.prop for obj in expression_obj])
            property_collector_options = vmodl.query.PropertyCollector.RetrieveOptions()
            prop_results = property_collector.RetrievePropertiesEx([filter_spec], property_collector_options)
            totalProps = []
            totalProps += prop_results.objects
            # RetrievePropertiesEx will only retrieve a subset of properties.
            # So need to use ContinueRetrievePropertiesEx
            while prop_results.token:
                prop_results = property_collector.ContinueRetrievePropertiesEx(token=prop_results.token)
                totalProps += prop_results.objects
            view_obj = filter_results(totalProps, value=[obj.value for obj in expression_obj],
                                      operator=[obj.operator for obj in expression_obj])
        else:
            view_obj = view

        return view_obj

    def break_down_cookie(self, cookie):
        """ Breaks down vSphere SOAP cookie
        :param cookie: vSphere SOAP cookie
        :type cookie: str
        :return: Dictionary with cookie_name: cookie_value
        """
        cookie_a = cookie.split(';')
        cookie_name = cookie_a[0].split('=')[0]
        cookie_text = ' {0}; ${1}'.format(cookie_a[0].split('=')[1],
                                          cookie_a[1].lstrip())
        self.cookies = {cookie_name: cookie_text}


class VirtMachine:
    """
    VirtMachine class holds Vcenter object and VM object and provides snapshot methods of create and get

    """
    def __init__(self, vmname, vcenter, vm_obj=None):
        self.vcenter = vcenter
        if not vm_obj:
            self.vm_obj = vcenter.get_container_view(view_type=[vim.VirtualMachine],
                                                     filter_expression='name == {}'.format(vmname))[0]
        else:
            self.vm_obj = vm_obj
        self.vmname = self.vm_obj.name

    def create_snapshot(self, name, description, quiesce=False, dump_memory=True):

        print("Creating snapshot {} for virtual machine \n\nWaiting for Snapshot task to complete ...".format(
            name, self.vmname))

        task.WaitForTask(self.vm_obj.CreateSnapshot(name=name,
                                                   description=description,
                                                   memory=dump_memory,
                                                   quiesce=quiesce))
        # lets grab the vmobj again to keep it updated
        self.vm_obj = self.vcenter.get_container_view(view_type=[vim.VirtualMachine],
                                                      filter_expression='name == {}'.format(self.vmname))[0]

    def get_snapshot(self):
        curr_snap = self.vm_obj.snapshot.currentSnapshot
        current_snap_obj = self._get_current_snap_obj(
            self.vm_obj.snapshot.rootSnapshotList, curr_snap)
        current_snapshot = "Name: {}; Description: {]; " \
                           "CreateTime: {}; State: {}".format(
                               current_snap_obj[0].name,
                               current_snap_obj[0].description,
                               current_snap_obj[0].createTime,
                               current_snap_obj[0].state)
        print("Virtual machine {} current snapshot is:".format(self.vm_obj.name))
        return current_snapshot

    def _get_current_snap_obj(self, snapshots, snap_ref):
        snap_obj = []
        for snapshot in snapshots:
            if snapshot.snapshot == snap_ref:
                snap_obj.append(snapshot)
            snap_obj = snap_obj + self._get_current_snap_obj(
                snapshot.childSnapshotList, snap_ref)
        return snap_obj


class ExportVM(VirtMachine):
    """
    ExportVM class inherits from VirtMachine class and handles the Exporting of a VM object
    """
    # TODO: Need to provide a method for exporting the memory snapshot file .VMSN

    def __init__(self, vcenter, vmname, destination_path, vm_obj=None):
        VirtMachine.__init__(self, vcenter=vcenter, vmname=vmname, vm_obj=vm_obj)
        self.destination = destination_path

    def print_http_nfc_lease_info(self):
        """ Prints information about the lease,
        such as the entity covered by the lease,
        and HTTP URLs for up/downloading file backings.
        :param info:
        :type info: vim.HttpNfcLease.Info
        :return:
        """
        info = self.http_nfc_lease.info
        print('Lease timeout: {0.leaseTimeout}\n' \
              'Disk Capacity KB: {0.totalDiskCapacityInKB}'.format(info))
        device_number = 1
        if info.deviceUrl:
            for device_url in info.deviceUrl:
                print('HttpNfcLeaseDeviceUrl: {1}\n' \
                      'Device URL Import Key: {0.importKey}\n' \
                      'Device URL Key: {0.key}\n' \
                      'Device URL: {0.url}\n' \
                      'Device URL Size: {0.fileSize}\n' \
                      'SSL Thumbprint: {0.sslThumbprint}\n'.format(device_url,
                                                                   device_number))
                device_number += 1
        else:
            print('No devices were found.')

    def download_device(self, headers, cookies, temp_target_disk,
                        device_url, lease_updater,
                        total_bytes_written, total_bytes_to_write):
        """ Download disk device of HttpNfcLease.info.deviceUrl
        list of devices
        :param headers: Request headers
        :type cookies: dict
        :param cookies: Request cookies (session)
        :type cookies: dict
        :param temp_target_disk: file name to write
        :type temp_target_disk: str
        :param device_url: deviceUrl.url
        :type device_url: str
        :param lease_updater:
        :type lease_updater: LeaseProgressUpdater
        :param total_bytes_written: Bytes written so far
        :type total_bytes_to_write: long
        :param total_bytes_to_write: VM unshared storage
        :type total_bytes_to_write: long
        :return:
        """
        with open(temp_target_disk, 'wb') as handle:
            response = requests.get(device_url, stream=True,
                                    headers=headers,
                                    cookies=cookies, verify=False)
            # response other than 200
            if not response.ok:
                response.raise_for_status()
            # keeping track of progress
            current_bytes_written = 0
            for block in response.iter_content(chunk_size=2048):
                # filter out keep-alive new chunks
                if block:
                    handle.write(block)
                    handle.flush()
                    os.fsync(handle.fileno())
                # getting right progress
                current_bytes_written += len(block)
                written_pct = ((current_bytes_written +
                                total_bytes_written) * 100) / total_bytes_to_write
                # updating lease
                lease_updater.progressPercent = int(written_pct)
        return current_bytes_written

    def prepare_export(self):

        # VM does exist
        if not self.vm_obj:
            print('VM {} does not exist'.format(self.vmname))
            sys.exit(1)

        # VM must be powered off to export
        if not self.vm_obj.runtime.powerState == \
                vim.VirtualMachine.PowerState.poweredOff:
            print('VM {} must be powered off'.format(self.vm_obj.name))
            sys.exit(1)

        # Breaking down SOAP Cookie &
        # creating Header
        soap_cookie = self.vcenter.si._stub.cookie
        self.vcenter.break_down_cookie(soap_cookie)
        self.http_headers = {'Accept': 'application/x-vnd.vmware-streamVmdk'}  # not required
        self._validate_destination(self.destination)

    def export(self):

        # Getting HTTP NFC Lease
        self.http_nfc_lease = self.vm_obj.ExportVm()

        # starting lease updater
        self.lease_updater = LeaseProgressUpdater(self.http_nfc_lease, 10)
        self.lease_updater.start()

        # Creating list for ovf files which will be value of
        # ovfFiles parameter in vim.OvfManager.CreateDescriptorParams
        ovf_files = []
        total_bytes_written = 0
        # http_nfc_lease.info.totalDiskCapacityInKB not real
        # download size
        total_bytes_to_write = self.vm_obj.summary.storage.unshared
        try:
            while True:
                if self.http_nfc_lease.state == vim.HttpNfcLease.State.ready:
                    print('HTTP NFC Lease Ready')
                    self.print_http_nfc_lease_info()

                    for deviceUrl in self.http_nfc_lease.info.deviceUrl:
                        if not deviceUrl.targetId:
                            print("No targetId found for url: {}." \
                                  .format(deviceUrl.url))
                            print("Device is not eligible for export. This " \
                                  "could be a mounted iso or img of some sort")
                            print("Skipping...")
                            continue

                        temp_target_disk = os.path.join(self.destination,
                                                        deviceUrl.targetId)
                        print('Downloading {} to {}'.format(deviceUrl.url,
                                                            temp_target_disk))
                        current_bytes_written = self.download_device(
                            headers=self.http_headers, cookies=self.vcenter.cookies,
                            temp_target_disk=temp_target_disk,
                            device_url=deviceUrl.url,
                            lease_updater=self.lease_updater,
                            total_bytes_written=total_bytes_written,
                            total_bytes_to_write=total_bytes_to_write)
                        # Adding up file written bytes to total
                        total_bytes_written += current_bytes_written
                        print('Creating OVF file for {}'.format(temp_target_disk))
                        # Adding Disk to OVF Files list
                        ovf_file = vim.OvfManager.OvfFile()
                        ovf_file.deviceId = deviceUrl.key
                        ovf_file.path = deviceUrl.targetId
                        ovf_file.size = current_bytes_written
                        ovf_files.append(ovf_file)
                    break
                elif self.http_nfc_lease.state == vim.HttpNfcLease.State.initializing:
                    print('HTTP NFC Lease Initializing.')
                elif self.http_nfc_lease.state == vim.HttpNfcLease.State.error:
                    print("HTTP NFC Lease error: {}".format(
                        self.http_nfc_lease.state.error))
                    sys.exit(1)
                sleep(2)
            print('Getting OVF Manager')
            ovf_manager = self.vcenter.si.content.ovfManager
            print('Creating OVF Descriptor')
            vm_descriptor_name = self.vm_obj.name
            ovf_parameters = vim.OvfManager.CreateDescriptorParams()
            ovf_parameters.name = vm_descriptor_name
            ovf_parameters.ovfFiles = ovf_files
            vm_descriptor_result = ovf_manager.CreateDescriptor(obj=self.vm_obj,
                                                                cdp=ovf_parameters)
            if vm_descriptor_result.error:
                raise vm_descriptor_result.error[0].fault
            else:
                vm_descriptor = vm_descriptor_result.ovfDescriptor
                target_ovf_descriptor_path = os.path.join(self.destination,
                                                          vm_descriptor_name +
                                                          '.ovf')
                print('Writing OVF Descriptor {}'.format(
                    target_ovf_descriptor_path))
                with open(target_ovf_descriptor_path, 'wb') as handle:
                    handle.write(vm_descriptor.encode('utf-8'))
                # ending lease
                self.http_nfc_lease.HttpNfcLeaseProgress(100)
                self.http_nfc_lease.HttpNfcLeaseComplete()
                # stopping thread
                self.lease_updater.stop()
        except Exception as ex:
            print(ex)
            # Complete lease upon exception
            self.http_nfc_lease.HttpNfcLeaseComplete()
            sys.exit(1)

    def _validate_destination(self, path):
        try:
            # checking if working directory exists
            print('Working dir: {} '.format(path))
            if not os.path.isdir(path):
                print('Creating working directory {}'.format(path))
                os.mkdir(path)
            # actual target directory for VM
            target_directory = os.path.join(path, self.vm_obj.name)
            print('Target dir: {}'.format(target_directory))
            if not os.path.isdir(target_directory):
                print('Creating target dir {}'.format(target_directory))
                os.mkdir(target_directory)
            self.destination = target_directory
        except Exception as ex:
            print(ex.message)
            raise ex


class LinkedClone(VirtMachine):
    """
    This class handles the cloning operations. It inherits from VirtMachine Class
    """

    def __init__(self, vmname, dest_vm_name, vcenter):
        VirtMachine.__init__(self, vmname=vmname, vcenter=vcenter)
        self.cloned_vm = None
        self.dest_vmname = dest_vm_name
        self.cluster = self._get_vm_cluster_from_obj(self.vm_obj)
        self.datacenter = self._get_datacenter_from_obj(self.vm_obj)
        self.dest_host = self._get_dest_vmhost()
        self.vm_folder = self.datacenter.vmFolder
        self.RelocationSpec = self._get_relocation_spec()
        self.snapshot = None

    def _get_datacenter_from_obj(self, obj=None):
        """
        recursive function to crawl up the tree to find the datacenter
        :param obj:
        :return:
        """
        if not obj:
            obj = self.vm_obj

        if not isinstance(obj, vim.Datacenter):
            try:
                tmp = obj.parent
            except:
                # default value if no DC is found
                return CustomObject({"name": "0319"})

            return self._get_datacenter_from_obj(obj.parent)
        else:
            return obj

    def _get_vm_cluster_from_obj(self, obj=None):
        """
        Pass a VM object and this will return the cluster that object belongs to. this implies that
        the Vm is part of a cluster. This will fail if the Vm is not in a cluster.
        :param obj:
        :return:
        """

        if not obj:
            obj = self.vm_obj

        if isinstance(obj, vim.VirtualMachine):
            return obj.resourcePool.owner
        elif isinstance(obj, vim.HostSystem):
            if isinstance(obj.parent, vim.ClusterComputeResource):
                return obj.parent
        elif isinstance(obj, vim.ClusterComputeresource):
            return obj
        elif isinstance(obj, vim.ResourcePool):
            return obj.owner

        return None

    def _get_dest_vmhost(self):
        for vmhost in self.cluster.host:
            if vmhost and vmhost.runtime.connectionState == 'connected':
                return vmhost

    def _get_relocation_spec(self):
        spec = vim.vm.RelocateSpec()
        spec.diskMoveType = 'createNewChildDiskBacking'
        spec.host = self.dest_host
        return spec

    def clone_vm(self):
        clone_spec = vim.vm.CloneSpec(
            powerOn=False, template=False, location=self.RelocationSpec,
            snapshot=self.get_snapshot())
        print("Creating Linked Clone {} from virtual machine {} \n\nWaiting for Clone task to complete ...".format(
            self.dest_vmname,
            self.vm_obj.name))

        task.WaitForTask(self.vm_obj.Clone(name=self.dest_vmname, folder=self.vm_folder, spec=clone_spec))
        self.cloned_vm = self.vcenter.get_container_view(view_type=[vim.VirtualMachine],
                                                         filter_expression='name == {}'.format(self.dest_vmname))[0]

    def get_snapshot(self):
        curr_snap = self.vm_obj.snapshot.currentSnapshot
        # current_snap_obj = self._get_current_snap_obj(
        #     self.vm_obj.snapshot.rootSnapshotList, curr_snap)
        return curr_snap


class LeaseProgressUpdater(threading.Thread):
    """
        Lease Progress Updater & keep alive
        thread.
        HttpNfcLease will expire if not constantly updated

        code pulled directly from the pyvmomi sample file export_vm.py with little modifications
    """
    def __init__(self, http_nfc_lease, update_interval):
        threading.Thread.__init__(self)
        self._running = True
        self.httpNfcLease = http_nfc_lease
        self.updateInterval = update_interval
        self.progressPercent = 0
        self.prev_progressPercent = -1

    def set_progress_pct(self, progress_pct):
        self.progressPercent = progress_pct

    def stop(self):
        self._running = False

    def run(self):
        while self._running:
            try:
                if self.httpNfcLease.state == vim.HttpNfcLease.State.done:
                    return
                # don't want a screen full of current percent complete, so lets store the percent and check whether
                # it changed.
                if not self.prev_progressPercent == self.progressPercent:
                    self.prev_progressPercent = self.progressPercent
                    print('Updating HTTP NFC Lease ' \
                          'Progress to {}%'.format(self.progressPercent))
                self.httpNfcLease.HttpNfcLeaseProgress(self.progressPercent)
                sleep(self.updateInterval)
            except Exception as ex:
                print(ex.message)
                return


def main():
    args = Args()
    # ssl context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    # connect to vc
    vc = Vcenter(name=args.vcenter,
                 username=args.username,
                 password=args.get(),
                 ssl_context=ssl_context)
    vc.connect()

    # generate an md5 hash of the name and date to use for the clone
    md5 = hashlib.md5((str(args.vm)+str(datetime.now().ctime())).encode('utf-8')).hexdigest()
    # define the name for the clone using the first 16 char of the md5 hash
    clone_name = "{}_ITSecExport_{}".format(args.vm, md5[0:16])

    # initialize the src_vm
    src_vm = LinkedClone(vcenter=vc,
                         vmname=args.vm,
                         dest_vm_name=clone_name)
    # snap the src_vm
    src_vm.create_snapshot(name="ITSecurity_snapshot_{}".format(md5[0:16]),
                           description="Snapshot in preparation for IT Security Clone on {}".format(
                               datetime.now().ctime()),
                           )
    # clone the src_vm
    src_vm.clone_vm()

    # initialize the ExportVM object
    exp_job = ExportVM(vcenter=vc,
                       vmname=src_vm.cloned_vm.name,
                       vm_obj=src_vm.cloned_vm,
                       destination_path="{}".format(os.path.join(args.destination, args.vm))
                       )
    # prep the export
    exp_job.prepare_export()
    # export the cloned vm
    exp_job.export()

    # disconnect from vCenter
    vc.disconnect()


def get_logger(name):
    """
    This is currently broken for this program. It was pulled from a different file but has not been modified
    to work with this file. Minor modifications are needed to get it right.

    For logging purposes each function or thread will need a new logger to log to the appropriate file.
    This function will check the global dict variable loggers for a logger with the name provided,
     if found then it will return that logger, otherwise it will create a new logger.
    Using this method instead of logging.config.dictConfig() so as to prevent duplicate logging
    Admittedly, this is a workaround instead of trying to figure out how to utilize the built-in dictConfig()
     method properly and not have duplicate log entries.
    The overhead for this below method is minimal and works.
    :param name:
    :return:
    """
    global DEBUG_MODE
    global MOREF_TYPE
    global LOG_LEVEL
    global LOG_SIZE
    global LOG_DIR
    global MAX_KEEP
    global PATH_SEPARATOR
    global LOGGERS

    if platform.system() == 'Windows':
        PATH_SEPARATOR = '\\'
    else:
        PATH_SEPARATOR = '/'

    if DEBUG_MODE:
        LOG_LEVEL = logging.DEBUG
    else:
        LOG_LEVEL = logging.INFO

    if MOREF_TYPE == 'VM':
        file_prefix = 'vm_'
    elif MOREF_TYPE == 'HOST':
        file_prefix = 'esxi_'
    else:
        file_prefix = ''

    if loggers.get(name):
        return loggers.get(name)
    else:
        formatter = logging.Formatter("%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s")

        logsize = int(LOG_SIZE) * 1048576

        logger = logging.getLogger(name)
        logger.setLevel(LOG_LEVEL)

        dfh = logging.StreamHandler(stream=sys.stdout)
        dfh.setLevel(logging.DEBUG)
        dfh.setFormatter(formatter)

        lfh = logging.handlers.RotatingFileHandler(LOG_DIR + PATH_SEPARATOR + file_prefix + 'get_metrics.log',
                                                       mode='a',
                                                       maxBytes=int(logsize),
                                                       backupCount=int(MAX_KEEP),
                                                       encoding='utf8',
                                                       delay=False)
        lfh.setLevel(logging.INFO)
        lfh.setFormatter(formatter)

        efh = logging.handlers.RotatingFileHandler(LOG_DIR + PATH_SEPARATOR + file_prefix + 'get_metrics_error.log',
                                                       mode='a',
                                                       maxBytes=int(logsize),
                                                       backupCount=int(MAX_KEEP),
                                                       encoding='utf8',
                                                       delay=False)
        efh.setLevel(logging.ERROR)
        efh.setFormatter(formatter)

        logger.addHandler(lfh)
        logger.addHandler(efh)

        loggers.update({name: logger})

        return logger


if __name__ == '__main__':
    main()
