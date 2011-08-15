import sys
import coffobject
import re
import struct
import argparse

def iprint(s):
    print "+++ %s"%s

def eprint(s):
    print "--- %s"%s

def wprint(s):
    print "*** %s"%s

#special reloc classes, name is important
#these classes handle the patching of different relocation types
class Reloc_Base(object):
    def __init__(self,coffobject,sectionName,relocObject):
        self.o = coffobject
        self.sectionName = sectionName 
        self.relocObject = relocObject
class Reloc_I386_DIR32(Reloc_Base):
    patchtemplate = \
    """
    ;%(comment)s
    call getBaseAddress
    mov ebx,eax
    add eax,%(relocOffset)s
    add ebx,%(relocValue)s
    mov [eax],ebx
    """
    def getPatchAssembly(self,linkeroutput):
        relocOffset = linkeroutput.getSectionAddress(self.o.fName+self.sectionName) \
                + self.relocObject.virtual_address
        curRelocContents = linkeroutput.getRawSections()[relocOffset:relocOffset+4]
        curRelocContents = struct.unpack('L',curRelocContents)[0]
        sti = self.relocObject.symbol_table_index
        sym = self.o.symbol_table.symbol_table_entry[sti]
        symName = self.o.symbolToName(sym)
        comment = "reloc should Point To %s + 0x%04x"%(symName,curRelocContents)
        relocValue = linkeroutput.lookUpSymbolAddressInOutput(symName,checkFirst=self.o)+curRelocContents
        return self.patchtemplate%locals()
    
class Reloc_I386_REL32(Reloc_Base):
    def getPatchAssembly(self,linkeroutput):
        relocOffset = linkeroutput.getSectionAddress(self.o.fName+self.sectionName) \
            + self.relocObject.virtual_address
        sti = self.relocObject.symbol_table_index
        sym = self.o.symbol_table.symbol_table_entry[sti]
        symName = self.o.symbolToName(sym)
        relocValue = linkeroutput.lookUpSymbolAddressInOutput(symName)
        b = linkeroutput.getRawSections()
        b = b[:relocOffset] + struct.pack("l",-4+relocValue-relocOffset) + b[relocOffset+4:]
        linkeroutput.setRawSections(b)
        return '' # this is a compile time patch so doesnt need any assembly
        
        
#    I386_DIR16,
#    I386_REL16,
#    I386_DIR32,
#    I386_DIR32NB,
#    I386_SEG12,
#    I386_SECTION,
#    I386_SECREL,
#    I386_TOKEN,
#    I386_SECREL7,
#end special reloc classes


#there are special symbols defined as common
#by gcc,  these can be merged
class CommSymContainer(object):
    def __init__(self):
        self.symbolMap = {}
    def addSymbol(self,symname,size):
        if symname in self.symbolMap:
            if self.symbolMap[symname] < size:
                self.symbolMap[symname]
        else:
            self.symbolMap[symname] = size
    def getOffset(self,symname):
        symnames = self.symbolMap.keys()
        symnames.sort()
        if symname not in symnames:
            return None
        curoffset = 0
        for x in symnames:
            if symname == x:
                return curoffset
            curoffset+= self.symbolMap[x]
    def getSection(self):
        return '\x00'*sum(self.symbolMap.values())



class LinkerOutput(object):
    def __init__(self,objects):
        self.outbin = ''
        self.asmOutput = 'use32\n'
        self.outlisting = {}
        self.position = 0
        self.objects = objects
        self.commSyms = CommSymContainer()
        for o in self.objects:
            commsyms = o.getCommSymbols()
            for s in commsyms:
                iprint('found a common symbol %s'%s)
                symEntrySize = o.lookUpSymbol(s).value
                self.commSyms.addSymbol(s,symEntrySize)# this merges symbols for us
        iprint("adding common symbols to output")
        self.addSection("_COMMONSYMBOLS_",self.commSyms.getSection())
    def getRawSections(self):
        return self.outbin
    def setRawSections(self,b):
        self.outbin = b
    def getOutput(self):
        outasm = self.asmOutput
        entryoffset = self.lookUpSymbolAddressInOutput('_entry')
        outasm += \
        """
        call getBaseAddress
        add eax,%(entryoffset)s
        push eax
        ret ; this is a jump to entry symbol
        getBaseAddress: ;uses eip to find start of shellcode
            call next___
            next___:
            pop eax
            add eax,5
            ret
        BaseAddress:
        %(outbin)s
        """
        outbin = "db "
        for b in self.outbin:
            outbin += str(ord(b))+','
        outbin=outbin[:-1]
        return outasm%locals()
    def processReloc(self,reloc):
        self.asmOutput += reloc.getPatchAssembly(self)
    def addSection(self,k,v):
        self.outlisting[k] = self.position
        self.outbin += v
        self.position += len(v)
    def getSectionAddress(self,k):
        return self.outlisting[k]
    def lookUpSymbolAddressInOutput(self,symname,checkFirst=None):
        iprint("attempting to find %s location in output"%symname)
        if checkFirst != None:#shift check first to front of list
            objects = set(self.objects)-set([checkFirst])
            objects = list(objects)
            objects = [checkFirst] + objects 
        else:
            objects = self.objects
        for o in objects:
            iprint("checking object file %s"%o.fName)
            s = o.lookUpSymbol(symname)
            if s == None:
                continue # symbol might be in ne
            if s.section_number != 'UNDEFINED':
                sname = o.sectionNameFromIndex(s.section_number)
                secOffsetKey = o.fName+sname
                offsetInSec = s.value
                iprint("%s was found in %s + 0x%02x"%
                            (symname,secOffsetKey,offsetInSec))
                return self.getSectionAddress(secOffsetKey)+offsetInSec
        #undefined symbol that is a comm symbol symbol
        commsymoffset = self.commSyms.getOffset(symname)
        if commsymoffset != None:
            return commsymoffset+self.getSectionAddress("_COMMONSYMBOLS_")
        eprint("cannot find requested symbol %s"%symname)
        raise Exception("cannot find symbol %s"%symname)
        
        


    
class Linker(object):
    def link(self,fnames,relocsAllowed=False):
        processed = []
        for fname in fnames:
            processed += [self.processObjectFile(fname)]
        return self.formOutput(processed,relocsAllowed)
        
    def formOutput(self,infodicts,relocsAllowed):
        objects = [x['o'] for x in infodicts]
        out = LinkerOutput(objects)
        for infodict in infodicts:
            o = infodict['o']
            data = infodict['data']
            for k in data.keys():
                iprint("adding %s to output"%k)
                out.addSection(k,data[k])
        for infodict in infodicts:
            for r in infodict['relocs']:
                if not relocsAllowed:
                    if r not in [Reloc_I386_REL32]:
                        raise Exception('a reloc type that requires -r was found')
                out.processReloc(r)
        return out.getOutput()
        
    def processObjectFile(self,fname):
        iprint('opening file %s'%fname)
        o = coffobject.CoffObject(fname)
        if o.coff_header.machine_type != 'I386':
            eprint('machine type %s is unsupported'%o.coff_header.machine_type)
            raise Exception("cannot continue with unsupported machine")
        data = self.getSectionData(o)
        relocs = self.getRelocations(o)
        name = o.fName
        return locals()
    def getSectionData(self,o):
        iprint("extracting section data")
        ret = {}
        for n in ['.text','.data','.rdata','.bss']:
            retkey  = o.fName+n
            d = o.getSectionData(n)
            if d == None:
                continue
            ret[retkey] = d
            iprint("section %s found with size %d"%(n,len(ret[retkey])))
        return ret
    def getRelocations(self,o):
        ret = []
        iprint("scanning for relocations")
        for n in ['.text','.data','.rdata','.bss']:
            for r in o.getRelocations(n):
                try:
                    className = "Reloc_"+str(r.type)
                    classObject = globals()[className]
                    ret.append(classObject(o,n,r))
                    iprint("created reloc of type %s in section %s"%(r.type,n))
                except Exception as e:
                    wprint("unable to create reloc %s in section %s"%(r.type,n))
                    raise e
        return ret


desc = \
'''
Converts coffobject files (.o) built by mingw into an assembly file that
can be built using nasm. When built using flat binary output
this results in position independant shellcode generated by
the c compiler. The object files must define an entry point function
called 'entry'
'''

parser = argparse.ArgumentParser(description=desc)
parser.add_argument('-r', '--relocs', action='store_true',default=False,
help="Whether relocation patching is allowed. Linking will fail if there\
are global pointer references in the object files and this flag is not set.\
the downside to this flag is that the executing code will need to be in \
writeable memory if any relocations need to be patched.")
parser.add_argument('-o', '--output',required=True)
parser.add_argument('object',nargs='+')

def main():
    args = parser.parse_args()    
    l = Linker()
    o = l.link(args.object,args.relocs)
    open(args.output,'w').write(o)

if __name__ == '__main__':
    main()


