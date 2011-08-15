from construct import *
import re

#using construct http://construct.wikispaces.com/
#https://github.com/MostAwesomeDude/construct
#parsing coff object using the following specification
# http://msdn.microsoft.com/en-us/windows/hardware/gg463119

symbol_table_entry = Struct("symbol_table_entry",
    Union(  "name_union",
            Struct("int_name",ULInt32("zeros"),ULInt32("offset")),
            String("name", 8, padchar = "\x00")
         ),
    ULInt32("value"),
    Enum(ExprAdapter(SLInt16("section_number"),
            encoder = lambda obj, ctx: obj + 1,
            decoder = lambda obj, ctx: obj - 1,
        ),
        UNDEFINED = -1,
        ABSOLUTE = -2,
        DEBUG = -3,
        _default_ = Pass,
    ),
    Enum(ULInt8("complex_type"),
        NULL = 0,
        POINTER = 1,
        FUNCTION = 2,
        ARRAY = 3,
         _default_ = Pass,
    ),
    Enum(ULInt8("base_type"),
        NULL = 0,
        VOID = 1,
        CHAR = 2,
        SHORT = 3,
        INT = 4,
        LONG = 5,
        FLOAT = 6,
        DOUBLE = 7,
        STRUCT = 8,
        UNION = 9,
        ENUM = 10,
        MOE = 11,
        BYTE = 12,
        WORD = 13,
        UINT = 14,
        DWORD = 15,
         _default_ = Pass,
    ),
    Enum(ULInt8("storage_class"),
        END_OF_FUNCTION = 255,
        NULL = 0,
        AUTOMATIC = 1,
        EXTERNAL = 2,
        STATIC = 3,
        REGISTER = 4,
        EXTERNAL_DEF = 5,
        LABEL = 6,
        UNDEFINED_LABEL = 7,
        MEMBER_OF_STRUCT = 8,
        ARGUMENT = 9,
        STRUCT_TAG = 10,
        MEMBER_OF_UNION = 11,
        UNION_TAG = 12,
        TYPE_DEFINITION = 13,
        UNDEFINED_STATIC = 14,
        ENUM_TAG = 15,
        MEMBER_OF_ENUM = 16,
        REGISTER_PARAM = 17,
        BIT_FIELD = 18,
        BLOCK = 100,
        FUNCTION = 101,
        END_OF_STRUCT = 102,
        FILE = 103,
        SECTION = 104,
        WEAK_EXTERNAL = 105,
         _default_ = Pass,
    ),
    ULInt8("number_of_aux_symbols"),
   #Array(lambda ctx: ctx.number_of_aux_symbols,
   #     Bytes("aux_symbols", 18)
   # )
)


CoffHeader = Struct("coff_header",
    Enum(ULInt16("machine_type"),
        UNKNOWN = 0x0,
        AM33 = 0x1d3,
        AMD64 = 0x8664,
        ARM = 0x1c0,
        EBC = 0xebc,
        I386 = 0x14c,
        IA64 = 0x200,
        M32R = 0x9041,
        MIPS16 = 0x266,
        MIPSFPU = 0x366,
        MIPSFPU16 = 0x466,
        POWERPC = 0x1f0,
        POWERPCFP = 0x1f1,
        R4000 = 0x166,
        SH3 = 0x1a2,
        SH3DSP = 0x1a3,
        SH4 = 0x1a6,
        SH5= 0x1a8,
        THUMB = 0x1c2,
        WCEMIPSV2 = 0x169,
        _default_ = Pass
    ),
    ULInt16("number_of_sections"),
    ULInt32("time_stamp"),
    ULInt32("symbol_table_pointer"),
    ULInt32("number_of_symbols"),
    ULInt16("optional_header_size"),
    FlagsEnum(ULInt16("characteristics"),
        RELOCS_STRIPPED = 0x0001,
        EXECUTABLE_IMAGE = 0x0002,
        LINE_NUMS_STRIPPED = 0x0004,
        LOCAL_SYMS_STRIPPED = 0x0008,
        AGGRESSIVE_WS_TRIM = 0x0010,
        LARGE_ADDRESS_AWARE = 0x0020,
        MACHINE_16BIT = 0x0040,
        BYTES_REVERSED_LO = 0x0080,
        MACHINE_32BIT = 0x0100,
        DEBUG_STRIPPED = 0x0200,
        REMOVABLE_RUN_FROM_SWAP = 0x0400,
        SYSTEM = 0x1000,
        DLL = 0x2000,
        UNIPROCESSOR_ONLY = 0x4000,
        BIG_ENDIAN_MACHINE = 0x8000,
    ),

)


section = Struct("section",
    String("name", 8, padchar = "\x00"),
    ULInt32("virtual_size"),
    ULInt32("virtual_address"),
    ULInt32("raw_data_size"),
    ULInt32("raw_data_pointer"),
    ULInt32("relocations_pointer"),
    ULInt32("line_numbers_pointer"),
    ULInt16("number_of_relocations"),
    ULInt16("number_of_line_numbers"),
    FlagsEnum(ULInt32("characteristics"), #pretty sure the alignment thing is wrong
        TYPE_REG = 0x00000000,
        TYPE_DSECT = 0x00000001,
        TYPE_NOLOAD = 0x00000002,
        TYPE_GROUP = 0x00000004,
        TYPE_NO_PAD = 0x00000008,
        TYPE_COPY = 0x00000010,
        CNT_CODE = 0x00000020,
        CNT_INITIALIZED_DATA = 0x00000040,
        CNT_UNINITIALIZED_DATA = 0x00000080,
        LNK_OTHER = 0x00000100,
        LNK_INFO = 0x00000200,
        TYPE_OVER = 0x00000400,
        LNK_REMOVE = 0x00000800,
        LNK_COMDAT = 0x00001000,
        MEM_FARDATA = 0x00008000,
        MEM_PURGEABLE = 0x00020000,
        MEM_16BIT = 0x00020000,
        MEM_LOCKED = 0x00040000,
        MEM_PRELOAD = 0x00080000,
        ALIGN_1BYTES = 0x00100000,
        ALIGN_2BYTES = 0x00200000,
        ALIGN_4BYTES = 0x00300000,
        ALIGN_8BYTES = 0x00400000,
        ALIGN_16BYTES = 0x00500000,
        ALIGN_32BYTES = 0x00600000,
        ALIGN_64BYTES = 0x00700000,
        ALIGN_128BYTES = 0x00800000,
        ALIGN_256BYTES = 0x00900000,
        ALIGN_512BYTES = 0x00A00000,
        ALIGN_1024BYTES = 0x00B00000,
        ALIGN_2048BYTES = 0x00C00000,
        ALIGN_4096BYTES = 0x00D00000,
        ALIGN_8192BYTES = 0x00E00000,
        LNK_NRELOC_OVFL = 0x01000000,
        MEM_DISCARDABLE = 0x02000000,
        MEM_NOT_CACHED = 0x04000000,
        MEM_NOT_PAGED = 0x08000000,
        MEM_SHARED = 0x10000000,
        MEM_EXECUTE = 0x20000000,
        MEM_READ = 0x40000000,
        MEM_WRITE = 0x80000000,        
    ),
    
    Pointer(lambda ctx: ctx.raw_data_pointer,
        Field("raw_data", lambda ctx: ctx.raw_data_size)
    ),
    
    Pointer(lambda ctx: ctx.line_numbers_pointer,
        Array(lambda ctx: ctx.number_of_line_numbers,
            Struct("line_numbers",
                ULInt32("type"),
                ULInt16("line_number"),
            )
        )
    ),
    
    Pointer(lambda ctx: ctx.relocations_pointer,
        Array(lambda ctx: ctx.number_of_relocations,
            Struct("relocations",
                ULInt32("virtual_address"),
                ULInt32("symbol_table_index"),
                Enum(    ULInt16('type'),
                        I386_ABSOLUTE = 0x0000,
                        I386_DIR16 = 0x0001,
                        I386_REL16 = 0x0002,
                        I386_DIR32 = 0x0006,
                        I386_DIR32NB = 0x0007,
                        I386_SEG12 = 0x0009,
                        I386_SECTION = 0x000A,
                        I386_SECREL = 0x000B,
                        I386_TOKEN = 0x000C,
                        I386_SECREL7 = 0x000D,
                        I386_REL32 = 0x0014,
                        _default_ = Pass
                        ),
            )
        )
    ),
)



_CoffObject = Struct( "CoffObject",
    CoffHeader,
    Array(lambda ctx: ctx.coff_header.number_of_sections, section),
    Pointer(lambda ctx: ctx.coff_header.symbol_table_pointer,
        Struct("symbol_table",
            Array(lambda ctx: ctx['_'].coff_header.number_of_symbols, symbol_table_entry),
            Struct("string_table",
                ULInt32("string_table_size"),
                Field("strings", lambda ctx: ctx.string_table_size-4)
            ),
        )
    )
)


class CoffObject(object):
    def __init__(self,fname):
        self.o = _CoffObject.parse_stream(open(fname,'rb'))
        self.fName = fname
    def getSectionByName(self,n):
        sec = [x for x in self.o.section if x.name == n]
        if(len(sec) == 0):
            return None
        assert(len(sec) == 1)
        return sec.pop()
    def getCommSymbols(self):
    	'''find symbols marked as .comm by gcc
    	These symbols need to be found and treated specially
    	'''
        # get .drective section might be better to check flags
        drective = self.getSectionByName('.drectve')
        if drective == None:
            drective = self.getSectionByName('.drective') #gcc seems to use the other
        if drective == None:
            return []
        #TODO is this broken? assert(drective.characteristics.LNK_INFO)
        sectiondata = drective.raw_data
        # scan through string finding all common symbols
        commonsyms = re.findall(r'\-aligncomm:"([A-Za-z_]+)"',sectiondata)
        return commonsyms
    def getSectionData(self,n):
        sec = self.getSectionByName(n)
        if(sec == None):
            return None
        if sec.characteristics.CNT_UNINITIALIZED_DATA:
            return sec.raw_data_size*'\x00'
        else:
            return sec.raw_data
    def getRelocations(self,n):
        sec = self.getSectionByName(n)
        if sec == None:
            return []
        return sec.relocations
    def symbolToName(self,s):
        if s.name_union.int_name.zeros == 0:
            strings = self.string_table.split('\0')
            return strings[s.name_union.int_name.offset]
        else:
            return s.name_union.name
    def lookUpSymbol(self,symname):
        it = self.symbol_table.symbol_table_entry.__iter__()
        try:
            while 1:
                s = it.next()
                if s.name_union.int_name.zeros == 0:
                    strings = self.string_table.split('\0')
                    n = strings[s.name_union.int_name.offset]
                    if symname == n:
                        return s
                else:
                    if s.name_union.name == symname:
                        return s
                for i in range(s.number_of_aux_symbols):
                    s=it.next() #skip over aux symbols
        except StopIteration:
            return None    
    def sectionNameFromIndex(self,i):
        assert(type(i) == int)
        return self.section[i].name
    def __repr__(self):
        return str(self.o)
    def __getattribute__(self,k):
        '''this is overloaded so we can access the wrapped construct object.'''
        try:
            return super(type(self),self).__getattribute__(k)
        except:
            return self.o.__getattribute__(k)

if __name__ == '__main__':# lets you dump a coff file for error checking
    import sys
    print CoffObject(sys.argv[1])

