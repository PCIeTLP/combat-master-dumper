#pragma once

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

void LogInit(const std::string& path);
void Log(const char* fmt, ...);
void LogClose();

struct Region {
    uint64_t base = 0, size = 0;
    uint32_t protect = 0, type = 0;
    bool writable = false, executable = false, isImage = false;
};

class Mem {
public:
    bool Open();
    void Close();

    bool Read(uint64_t addr, void* out, size_t n) const;

    uint64_t U64(uint64_t a) const { uint64_t v = 0; return Read(a, &v, 8) ? v : 0; }
    uint32_t U32(uint64_t a) const { uint32_t v = 0; return Read(a, &v, 4) ? v : 0; }
    uint16_t U16(uint64_t a) const { uint16_t v = 0; return Read(a, &v, 2) ? v : 0; }
    uint8_t  U8(uint64_t a)  const { uint8_t  v = 0; return Read(a, &v, 1) ? v : 0; }

    bool CStr(uint64_t a, std::string& out, size_t max = 512) const;
    std::string CStrOr(uint64_t a, const char* fallback = "") const {
        std::string s; return CStr(a, s) ? s : std::string(fallback);
    }

    void RefreshRegions();
    const std::vector<Region>& Regions() const { return regions_; }
    bool Contains(uint64_t a) const;
    const Region* RegionOf(uint64_t a) const;

    bool FindModule(const char* name, uint64_t& base, uint64_t& size) const;

    DWORD pid_ = 0;

private:
    std::vector<Region> regions_;
};

struct Layout {
    uint32_t cls_image = 0x00;
    uint32_t cls_self = 0x10;
    uint32_t cls_namespaze = 0x18;
    uint32_t cls_byval = 0x20;
    uint32_t cls_this = 0x30;
    uint32_t cls_declaring = 0x50;
    uint32_t cls_handle = 0x68;
    uint32_t cls_parent = 0x78;
    uint32_t cls_methods = 0x80;
    uint32_t cls_fields = 0x90;
    uint32_t cls_interfaces = 0x98;
    uint32_t cls_name = 0xA0;
    uint32_t cls_staticFields = 0xB8;
    uint32_t cls_instanceSize = 0xF8;
    uint32_t cls_flags = 0x118;
    uint32_t cls_methodCount = 0x120;
    uint32_t cls_fieldCount = 0x124;
    uint32_t cls_interfaceCount = 0x12C;
    uint32_t cls_span = 0x200;

    uint32_t fld_parent = 0x00, fld_token = 0x08, fld_name = 0x10,
             fld_type = 0x18, fld_offset = 0x20, fld_size = 0x28;

    uint32_t mth_ptr = 0x00, mth_klass = 0x18, mth_name = 0x20, mth_ret = 0x28,
             mth_params = 0x30, mth_handle = 0x38, mth_token = 0x48,
             mth_flags = 0x4C, mth_iflags = 0x4E, mth_slot = 0x50,
             mth_paramCount = 0x52, mth_paramCountWidth = 1, mth_size = 0x58;

    uint32_t img_nameNoExt = 0x08, img_name = 0x18, img_codeGenModule = 0x38, img_size = 0x48;

    uint32_t cgm_name = 0x00, cgm_methodCount = 0x08, cgm_methodPointers = 0x10;

    uint32_t td_nameIndex = 0x00, td_namespaceIndex = 0x04, td_flags = 0x10,
             td_methodStart = 0x18, td_methodCount = 0x34, td_fieldCount = 0x38,
             td_token = 0x48, td_size = 0x4C;

    int32_t md_nameIndex = 0x00;
    uint32_t md_size = 0x1E;
    int32_t md_token = -1;       int32_t md_tokenWidth = 0;
    int32_t md_returnType = -1;  int32_t md_returnWidth = 0;
    int32_t md_flags = -1, md_iflags = -1, md_slot = -1, md_paramCount = -1;

    uint32_t typ_data = 0x00, typ_bits = 0x08, typ_typeByte = 0x0A, typ_size = 0x10;
    uint32_t typ_byrefBit = 29;

    uint32_t gc_typeHandle = 0x00, gc_classInst = 0x08, gc_cachedClass = 0x18;
    uint32_t gi_argc = 0x00, gi_argv = 0x08;
};

enum Il2CppTypeEnum : uint8_t {
    IL2CPP_TYPE_END = 0x00, IL2CPP_TYPE_VOID = 0x01, IL2CPP_TYPE_BOOLEAN = 0x02,
    IL2CPP_TYPE_CHAR = 0x03, IL2CPP_TYPE_I1 = 0x04, IL2CPP_TYPE_U1 = 0x05,
    IL2CPP_TYPE_I2 = 0x06, IL2CPP_TYPE_U2 = 0x07, IL2CPP_TYPE_I4 = 0x08,
    IL2CPP_TYPE_U4 = 0x09, IL2CPP_TYPE_I8 = 0x0a, IL2CPP_TYPE_U8 = 0x0b,
    IL2CPP_TYPE_R4 = 0x0c, IL2CPP_TYPE_R8 = 0x0d, IL2CPP_TYPE_STRING = 0x0e,
    IL2CPP_TYPE_PTR = 0x0f, IL2CPP_TYPE_BYREF = 0x10, IL2CPP_TYPE_VALUETYPE = 0x11,
    IL2CPP_TYPE_CLASS = 0x12, IL2CPP_TYPE_VAR = 0x13, IL2CPP_TYPE_ARRAY = 0x14,
    IL2CPP_TYPE_GENERICINST = 0x15, IL2CPP_TYPE_TYPEDBYREF = 0x16, IL2CPP_TYPE_I = 0x18,
    IL2CPP_TYPE_U = 0x19, IL2CPP_TYPE_FNPTR = 0x1b, IL2CPP_TYPE_OBJECT = 0x1c,
    IL2CPP_TYPE_SZARRAY = 0x1d, IL2CPP_TYPE_MVAR = 0x1e,
    IL2CPP_TYPE_MAX = 0x1e,
};

enum {
    TYPE_ATTRIBUTE_VISIBILITY_MASK = 0x00000007,
    TYPE_ATTRIBUTE_NOT_PUBLIC = 0x0, TYPE_ATTRIBUTE_PUBLIC = 0x1,
    TYPE_ATTRIBUTE_NESTED_PUBLIC = 0x2, TYPE_ATTRIBUTE_NESTED_PRIVATE = 0x3,
    TYPE_ATTRIBUTE_NESTED_FAMILY = 0x4, TYPE_ATTRIBUTE_NESTED_ASSEMBLY = 0x5,
    TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM = 0x6, TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM = 0x7,
    TYPE_ATTRIBUTE_INTERFACE = 0x00000020,
    TYPE_ATTRIBUTE_ABSTRACT = 0x00000080, TYPE_ATTRIBUTE_SEALED = 0x00000100,
    TYPE_ATTRIBUTE_SERIALIZABLE = 0x00002000,

    FIELD_ATTRIBUTE_FIELD_ACCESS_MASK = 0x0007,
    FIELD_ATTRIBUTE_PRIVATE = 0x0001, FIELD_ATTRIBUTE_FAM_AND_ASSEM = 0x0002,
    FIELD_ATTRIBUTE_ASSEMBLY = 0x0003, FIELD_ATTRIBUTE_FAMILY = 0x0004,
    FIELD_ATTRIBUTE_FAM_OR_ASSEM = 0x0005, FIELD_ATTRIBUTE_PUBLIC = 0x0006,
    FIELD_ATTRIBUTE_STATIC = 0x0010, FIELD_ATTRIBUTE_INIT_ONLY = 0x0020,
    FIELD_ATTRIBUTE_LITERAL = 0x0040, FIELD_ATTRIBUTE_NOT_SERIALIZED = 0x0080,

    METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK = 0x0007,
    METHOD_ATTRIBUTE_PRIVATE = 0x0001, METHOD_ATTRIBUTE_FAM_AND_ASSEM = 0x0002,
    METHOD_ATTRIBUTE_ASSEM = 0x0003, METHOD_ATTRIBUTE_FAMILY = 0x0004,
    METHOD_ATTRIBUTE_FAM_OR_ASSEM = 0x0005, METHOD_ATTRIBUTE_PUBLIC = 0x0006,
    METHOD_ATTRIBUTE_STATIC = 0x0010, METHOD_ATTRIBUTE_FINAL = 0x0020,
    METHOD_ATTRIBUTE_VIRTUAL = 0x0040, METHOD_ATTRIBUTE_ABSTRACT = 0x0400,
    METHOD_ATTRIBUTE_SPECIAL_NAME = 0x0800, METHOD_ATTRIBUTE_RT_SPECIAL_NAME = 0x1000,
};

struct FieldDump {
    std::string name;
    uint64_t type = 0;
    uint32_t offset = 0;
    uint32_t token = 0;
    uint16_t attrs = 0;
    bool isStatic = false, isLiteral = false;
};

struct MethodDump {
    std::string name;
    uint64_t methodPtr = 0;
    uint64_t rva = 0;
    uint64_t returnType = 0;
    std::vector<uint64_t> paramTypes;
    uint32_t token = 0;
    uint16_t flags = 0, iflags = 0, slot = 0xFFFF;
    uint8_t paramCount = 0;
    bool fromRuntime = false;
};

struct ClassDump {
    uint64_t addr = 0;
    uint64_t image = 0;
    uint64_t handle = 0;
    uint64_t parent = 0;
    uint64_t declaring = 0;
    uint64_t staticFields = 0;
    std::string name, ns;
    uint32_t flags = 0;
    uint32_t token = 0;
    uint32_t instanceSize = 0;
    uint16_t declaredMethods = 0, declaredFields = 0;
    std::vector<uint64_t> interfaces;
    std::vector<FieldDump> fields;
    std::vector<MethodDump> methods;
    bool isGenericInst = false;
};

struct ImageDump {
    uint64_t addr = 0;
    std::string name, nameNoExt;
    uint64_t codeGenModule = 0;
    uint64_t methodPointers = 0;
    uint32_t methodPointerCount = 0;
    std::vector<size_t> classIdx;
};

struct FitRecord {
    std::string what;
    std::string value;
    int agree = 0, total = 0;
    bool fitted = false;
    bool critical = false;
};

struct Context {
    Mem mem;
    Layout L;
    uint64_t gaBase = 0, gaSize = 0;
    uint32_t gaTimeStamp = 0;
    uint32_t gaCheckSum = 0;
    std::string unityVersion;

    uint64_t heapLo = 0, heapHi = 0;
    std::vector<std::pair<uint64_t, uint64_t>> heapRanges;
    uint64_t strBase = 0;

    uint64_t methodDefTable = 0;
    bool methodDefTableValid = false;
    uint64_t typesArray = 0;
    uint32_t typesCount = 0;

    std::vector<ClassDump> classes;
    std::unordered_map<uint64_t, size_t> byAddr;
    std::unordered_map<uint64_t, size_t> byHandle;
    std::vector<ImageDump> images;
    std::unordered_map<uint64_t, size_t> imageByAddr;

    std::vector<FitRecord> fits;
    int metaCheckAgree = 0, metaCheckTotal = 0;

    uint64_t TypeAt(uint32_t idx) const {
        if (!typesArray || idx >= typesCount) return 0;
        return mem.U64(typesArray + (uint64_t)idx * 8);
    }

    bool InHeap(uint64_t a) const {
        for (const auto& r : heapRanges) if (a >= r.first && a < r.second) return true;
        return false;
    }
    bool InGA(uint64_t a) const { return a >= gaBase && a < gaBase + gaSize; }
    bool Ptr(uint64_t a) const { return a >= 0x10000 && mem.Contains(a); }

    bool IsType(uint64_t t) const {
        if (!Ptr(t)) return false;
        uint8_t k = mem.U8(t + L.typ_typeByte);
        return k >= IL2CPP_TYPE_VOID && k <= IL2CPP_TYPE_MAX;
    }

    void Note(const char* what, const std::string& value, int agree, int total,
              bool fitted, bool critical);
};

bool WaitForRuntime(Context& ctx, int seconds);
bool DetectStringHeap(Context& ctx);
bool FitClassIdentity(Context& ctx);
void ScanClasses(Context& ctx);
void FitClassLayout(Context& ctx);
void FitMemberLayout(Context& ctx);
void ResolveImages(Context& ctx);
void ReadMembers(Context& ctx);
void FitMetadataTables(Context& ctx);
void FillFromMetadata(Context& ctx);

std::string TypeName(Context& ctx, uint64_t type, int depth = 0);
std::string ClassFullName(Context& ctx, size_t idx);

void EmitDumpCs(Context& ctx, const std::string& path);
void EmitScriptJson(Context& ctx, const std::string& path);
void EmitIl2CppHeader(Context& ctx, const std::string& path);
void EmitLayoutJson(Context& ctx, const std::string& path);
void EmitHealthJson(Context& ctx, const std::string& path);
void EmitSummary(Context& ctx, const std::string& path);
void EmitIdaScript(const std::string& path);

int RunDump(const std::string& outDir);
