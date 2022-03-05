from typing import List, Callable, Any
import logging, struct, binascii

from volatility3.framework import renderers, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist
from volatility3.plugins import yarascan
import yara

# TODO change all infos to the proper name for production to debug =)
# https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/symbols/linux/extensions/__init__.py
golog = logging.getLogger(__name__)

YARA_GO = {
    "opcodes":
       'rule go_bytes { \
        strings:  $magic_bytes_lookup16 = {(FF FF FF FA | FA FF FF FF) 00 00 01 08}  \
        condition: $magic_bytes_lookup16 \
    }'
}


# used from_volshell for debuging

def ascii_bytes(bytes):
    """Converts bytes into an ascii string"""
    return "".join([chr(x) if 32 < x < 127 else '.' for x in binascii.unhexlify(bytes)])

def display_data(offset: int, remaining_data: bytes, format_string: str = "B", ascii: bool = True):
    """Display a series of bytes"""
    chunk_size = struct.calcsize(format_string)
    data_length = len(remaining_data)
    remaining_data = remaining_data[:data_length - (data_length % chunk_size)]

    data = ""
    while remaining_data:
        current_line, remaining_data = remaining_data[:16], remaining_data[16:]

        data_blocks = [current_line[chunk_size * i:chunk_size * (i + 1)] for i in range(16 // chunk_size)]
        data_blocks = [x for x in data_blocks if x != b'']
        valid_data = [("{:0" + str(2 * chunk_size) + "x}").format(struct.unpack(format_string, x)[0])
                        for x in data_blocks]
        padding_data = [" " * 2 * chunk_size for _ in range((16 - len(current_line)) // chunk_size)]
        hex_data = " ".join(valid_data + padding_data)

        ascii_data = ""
        if ascii:
            connector = " "
            if chunk_size < 2:
                connector = ""
            ascii_data = connector.join([ascii_bytes(x) for x in valid_data])

        data += f"{hex(offset)} {hex_data}   {ascii_data}\n"
        offset += 16
        
    
    return data


class Gopclntab():
    """
        [4] 0xfffffffa

        [2] 0x00 0x00

        [1] 0x01

        [1] 0x08
            [8] N (size of function symbol table)

            [8] pc0

            [8] func0 offset

            [8] pc1

            [8] func1 offset

            …

            [8] pcN

            [4] int32 offset from start to source file table

… and then data referred to by offset, in an unspecified order …  
    """
    PCLN_OFFSET = 6 #includes padding.

    QUANTUM_SIZE_OFFSET = PCLN_OFFSET + 1
    UINT_PTR_SIZE_OFFSET = QUANTUM_SIZE_OFFSET + 1

    FUNC_TABLE_OFFSET = UINT_PTR_SIZE_OFFSET + 8


    PC_BYTES = 8
    FUNC_BYTES = 8

    ENDIANESS = "little"

    def __init__(self, raw_bytes, proc_layer, offset) -> None:

        self.proc_layer = proc_layer
        self.offset = offset


        golog.info(raw_bytes)
        self.magic_bytes = raw_bytes[:self.PCLN_OFFSET]


        # self.magic 4
        # self.padding 4
        self.quantum = self._get_int(raw_bytes[self.PCLN_OFFSET:self.QUANTUM_SIZE_OFFSET]) #1

        self.ptr_size =  self._get_int(raw_bytes[self.QUANTUM_SIZE_OFFSET:self.UINT_PTR_SIZE_OFFSET]) # 1

        self.nfunctab = self._get_int(raw_bytes[self.UINT_PTR_SIZE_OFFSET:self.FUNC_TABLE_OFFSET]) # 8


        self.index = self.offset + self.FUNC_TABLE_OFFSET

        # TODO: Trying to figure out why the structure ordering seems incorrect.
        # the structure goes pc0 -> pcN however, it seems that after first couple it shows the symtab
        for i in range(self.nfunctab):
            raw_data = proc_layer.read(self.index, self.ptr_size*2, pad=True)

            pc_n = raw_data[:self.ptr_size]

            func_offset_n = raw_data[self.ptr_size:]

            golog.info(f"pcN: {self._get_int(pc_n)} : func_offset_n: {self._get_int(func_offset_n)}")
            golog.info(raw_data)

            self.index += (self.ptr_size*2)

            if i == 32: break

        self.index = self.offset + self.FUNC_TABLE_OFFSET

        with open("SYMBOL_DUMP.tmp", 'a+') as f:
            f.write(display_data(self.index, self.proc_layer.read(self.index, 0x1000)))


    
    def _get_int(self, b) -> int:
        return int.from_bytes(b, self.ENDIANESS)



class Go(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)

    _32BIT = False

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name='kernel', 
                description='Linux kernel',
                architectures=['Intel32', "Intel64"]
            ),
            requirements.ListRequirement(
                name = 'pid', 
                element_type=int,
                description="Process PIDS.",
                optional=True
            ),
            requirements.ListRequirement(
                name='procName',
                element_type=str,
                description='Proc name',
                optional=True
            )
        ]

    @classmethod
    def proc_name_filter(cls, pid_name_list: List[str] = None) -> Callable[[Any], bool]:
        """Constructs a filter function for process Names.
        Args:
            pid_name_list: List of process names that are acceptable (or None if all are acceptable)
        Returns:
            Function which, when provided a process object, returns True if the process is to be filtered out of the list
        """
        
        filter_list = [x for x in pid_name_list if x is not None]

        if filter_list:
            def filter_func(x):
                # get the string from the comm for the process name
                return utility.array_to_string(x.comm) not in filter_list

            return filter_func
        else:
            return lambda _: False # this means no filter

    def run(self):
        golog.info("Plugin is now Starting to Run!")

        filter_func = self.proc_name_filter(
            self.config.get('procName')
        )

        list_procs = pslist.PsList.list_tasks(
            self.context,
            self.config['kernel'],
            filter_func=filter_func
        )
        
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),

                ("Start", format_hints.Hex),
                ("End", format_hints.Hex),
                # ("Flags", str),
                # ("PgOff", format_hints.Hex), 
                # ("Major", int), 
                # ("Minor", int), 
                # ("Inode", int),
                # ("File Path", str),

            ],
            generator=self._generator(list_procs)
        )

    def _check_32bit(self, task, proc_layer) -> bool:

        for vma in task.mm.get_mmap_iter():
 
                start = vma.vm_start
                end = vma.vm_end

                

                vma_name = vma.get_name(self.context, task)
                
                # pulled from vols elf plugin determine if 32 or 64bit process
                hdr = proc_layer.read(vma.vm_start, 4, pad=True)

                if hdr[0] == 0x7f:
                    if not hdr[1] & 1: # if the first bit is not 1 that means its 32 bit.
                        return True

        return False


    def _generator(self, tasks):
        for task in tasks:
            if not task.mm:
                continue

            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            is_32bit = self._check_32bit(task, proc_layer)
            golog.info(f"Process: is 32-bit mode: {is_32bit}")


            pid = task.pid
            pid_str = str(pid)
            
            rules = yara.compile(sources=YARA_GO)
            for  offset, rule_name, name, value in proc_layer.scan(
                context=self.context,
                scanner=yarascan.YaraScanner(rules=rules),
                # sections=[(start, end-start)]

            ):
                # golog.info(f"{vma_name}: var")
                # golog.info(offset)
                # golog.info(f"")
                golog.info(hex(offset))
                raw_data = proc_layer.read(offset, 64)

                display_data(offset, raw_data)

                # golog.info(raw_data)

                go_pclntab = Gopclntab(raw_data, proc_layer, offset)
                # golog.info(raw_data)
                # self._display_data(offset, raw_data)
            
            exit(0)

            for vma in task.mm.get_mmap_iter():
 
                start = vma.vm_start
                end = vma.vm_end


                if start <= task.mm.brk and end >= task.mm.start_brk:
                    golog.info("heap region")

                    heap_data = proc_layer.read(start, 64)


                    self._display_data(start, heap_data)
                elif start <= task.mm.start_stack and end >= task.mm.start_stack:
                    golog.info("stack region")

                    stack_data = proc_layer.read(start, 64)
                    # self._display_data(start, stack_data)
                else:
                    try:
                        other_data = proc_layer.read(start, end-start)
                        # self._display_data(start, other_data)
                    except:
                        pass
                

            #     vma_name = vma.get_name(self.context, task)

                # continue

                # if vma_name != '/home/samz/Desktop/test': continue
                
                
                # physical_addr, physical_layer_name = self.context.layers[vma.vol.layer_name].translate(vma.vm_start.vol.offset)
                



                # physical_layer = self.context.layers[physical_layer_name]
                # golog.debug(f"Physical_addr {physical_addr}\nLayer_Name: {physical_layer_name}")
                # raw_bytes = physical_layer.read(physical_addr, end-start, pad=True)
                # raw_bytes = proc_layer.read(physical_addr, 32, pad=True)

                # self._display_data(16, raw_bytes)

                # self._display_data(physical_addr, raw_bytes)
                # golog.info("End of dump")
                # rules = yara.compile(sources=YARA_GO)
                # for  offset, rule_name, name, value in physical_layer.scan(
                #     context=self.context,
                #     scanner=yarascan.YaraScanner(rules=rules),
                #     # sections=[(start, end-start)]

                # ):
                #     golog.info(f"{vma_name}: var")
                #     golog.info(offset)
                #     # golog.info(f"")
                #     golog.info(physical_layer.read(offset, 16, pad=True))
                    # golog.info(f"off: {offset}\n rule_name: {rule_name}\n name: {name}\n value: {value}")


                # golog.info(physical_layer_name)
                # golog.info(vma.vol.layer_name)
                # self.context.layers[physical_layer_name].scan(
                #     #ctx
                #     #scanner
                #     #progresscallback
                #     #sections memory area to scan!

                # )