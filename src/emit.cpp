#include "dumper.h"
#include <algorithm>

static const char* TypeAccess(uint32_t f) {
    switch (f & TYPE_ATTRIBUTE_VISIBILITY_MASK) {
    case TYPE_ATTRIBUTE_NOT_PUBLIC:          return "internal";
    case TYPE_ATTRIBUTE_PUBLIC:              return "public";
    case TYPE_ATTRIBUTE_NESTED_PUBLIC:       return "public";
    case TYPE_ATTRIBUTE_NESTED_PRIVATE:      return "private";
    case TYPE_ATTRIBUTE_NESTED_FAMILY:       return "protected";
    case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:     return "internal";
    case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:return "private protected";
    case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM: return "protected internal";
    }
    return "internal";
}

static const char* MemberAccess(uint16_t f) {
    switch (f & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK) {
    case METHOD_ATTRIBUTE_PRIVATE:       return "private";
    case METHOD_ATTRIBUTE_FAM_AND_ASSEM: return "private protected";
    case METHOD_ATTRIBUTE_ASSEM:         return "internal";
    case METHOD_ATTRIBUTE_FAMILY:        return "protected";
    case METHOD_ATTRIBUTE_FAM_OR_ASSEM:  return "protected internal";
    case METHOD_ATTRIBUTE_PUBLIC:        return "public";
    }
    return "private";
}

static std::string JsonEsc(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
        case '"':  o += "\\\""; break;
        case '\\': o += "\\\\"; break;
        case '\n': o += "\\n";  break;
        case '\r': o += "\\r";  break;
        case '\t': o += "\\t";  break;
        default:
            if (c < 0x20 || c > 0x7E) { char b[8]; sprintf_s(b, "\\u%04X", c); o += b; }
            else o += (char)c;
        }
    }
    return o;
}

static std::string Sanitize(const std::string& s) {
    std::string o;
    for (char c : s) o += (isalnum((unsigned char)c) || c == '_') ? c : '_';
    if (o.empty() || isdigit((unsigned char)o[0])) o = "_" + o;
    return o;
}

static std::string FullName(Context& ctx, const ClassDump& c) {
    auto it = ctx.byAddr.find(c.addr);
    return it == ctx.byAddr.end() ? c.name : ClassFullName(ctx, it->second);
}

void EmitDumpCs(Context& ctx, const std::string& path) {
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "w") != 0 || !f) { Log("[!] cannot write %s", path.c_str()); return; }
    setvbuf(f, nullptr, _IOFBF, 1 << 22);

    fprintf(f, "// Dumped with combat-master-dumper\n");
    fprintf(f, "// GameAssembly.dll base 0x%llX  size 0x%llX  build %08X\n",
            ctx.gaBase, ctx.gaSize, ctx.gaTimeStamp);
    if (!ctx.unityVersion.empty()) fprintf(f, "// Unity %s\n", ctx.unityVersion.c_str());
    fprintf(f, "// %zu types across %zu assemblies\n\n", ctx.classes.size(), ctx.images.size());

    for (size_t ii = 0; ii < ctx.images.size(); ii++)
        fprintf(f, "// Image %zu: %s - %zu types\n", ii, ctx.images[ii].name.c_str(),
                ctx.images[ii].classIdx.size());
    fprintf(f, "\n");

    for (const ImageDump& im : ctx.images) {

        std::vector<size_t> idx = im.classIdx;
        std::sort(idx.begin(), idx.end(), [&](size_t a, size_t b) {
            const ClassDump& A = ctx.classes[a];
            const ClassDump& B = ctx.classes[b];
            if (A.ns != B.ns) return A.ns < B.ns;
            return A.name < B.name;
        });

        for (size_t ci : idx) {
            const ClassDump& c = ctx.classes[ci];
            if (c.isGenericInst) continue;

            bool isInterface = (c.flags & TYPE_ATTRIBUTE_INTERFACE) != 0;
            bool isAbstract = (c.flags & TYPE_ATTRIBUTE_ABSTRACT) != 0;
            bool isSealed = (c.flags & TYPE_ATTRIBUTE_SEALED) != 0;
            bool isSerializable = (c.flags & TYPE_ATTRIBUTE_SERIALIZABLE) != 0;

            std::string parentName, parentDisplay;
            if (c.parent) {
                auto it = ctx.byAddr.find(c.parent);
                if (it != ctx.byAddr.end()) {
                    parentName = FullName(ctx, ctx.classes[it->second]);

                    parentDisplay = TypeName(ctx, c.parent + ctx.L.cls_byval);
                    if (parentDisplay.empty() || parentDisplay == "object") parentDisplay = parentName;
                }
            }
            bool isEnum = parentName == "System.Enum";
            bool isStruct = parentName == "System.ValueType" || isEnum;

            fprintf(f, "// Namespace: %s\n", c.ns.c_str());
            if (isSerializable) fprintf(f, "[Serializable]\n");

            const char* kind = isInterface ? "interface" : isEnum ? "enum" : isStruct ? "struct" : "class";
            fprintf(f, "%s%s%s %s %s",
                    TypeAccess(c.flags),
                    (!isInterface && !isStruct && isAbstract) ? " abstract" : "",
                    (!isInterface && !isStruct && isSealed && !isAbstract) ? " sealed" : "",
                    kind, c.name.c_str());

            std::vector<std::string> bases;
            if (!isStruct && !isInterface && !parentName.empty() && parentName != "System.Object")
                bases.push_back(parentDisplay);
            for (uint64_t k : c.interfaces) {
                auto it = ctx.byAddr.find(k);
                if (it == ctx.byAddr.end()) continue;
                std::string n = TypeName(ctx, k + ctx.L.cls_byval);
                if (n.empty() || n == "object") n = FullName(ctx, ctx.classes[it->second]);
                bases.push_back(n);
            }
            for (size_t i = 0; i < bases.size(); i++)
                fprintf(f, "%s%s", i == 0 ? " : " : ", ", bases[i].c_str());

            fprintf(f, " // TypeDefIndex: 0x%X, Il2CppClass 0x%llX", c.token, c.addr);
            if (c.instanceSize) fprintf(f, ", instance_size 0x%X", c.instanceSize);
            if (c.staticFields) fprintf(f, ", static_fields 0x%llX", c.staticFields);
            fprintf(f, "\n{\n");

            if (!c.fields.empty()) {
                fprintf(f, "\t// Fields\n");
                for (const FieldDump& fd : c.fields) {
                    std::string tn = TypeName(ctx, fd.type);
                    fprintf(f, "\t%s %s%s%s%s %s;",
                            MemberAccess(fd.attrs),
                            (fd.isStatic && !fd.isLiteral) ? "static " : "",
                            fd.isLiteral ? "const " : "",
                            ((fd.attrs & FIELD_ATTRIBUTE_INIT_ONLY) && !fd.isLiteral) ? "readonly " : "",
                            tn.c_str(), fd.name.c_str());
                    if (fd.isLiteral) fprintf(f, " // literal");
                    else if (fd.isStatic && c.staticFields)
                        fprintf(f, " // static_fields+0x%X = 0x%llX", fd.offset, c.staticFields + fd.offset);
                    else fprintf(f, " // 0x%X", fd.offset);
                    fprintf(f, "\n");
                }
                fprintf(f, "\n");
            }

            if (!c.methods.empty()) {
                fprintf(f, "\t// Methods\n");
                for (const MethodDump& m : c.methods) {
                    fprintf(f, "\n");
                    if (m.rva) fprintf(f, "\t// RVA: 0x%llX VA: 0x%llX\n", m.rva, m.methodPtr);
                    else fprintf(f, "\t// RVA: -1 (not resolved)\n");
                    std::string ret = m.returnType ? TypeName(ctx, m.returnType) : "void";
                    fprintf(f, "\t%s %s%s%s%s %s(",
                            MemberAccess(m.flags),
                            (m.flags & METHOD_ATTRIBUTE_STATIC) ? "static " : "",
                            (m.flags & METHOD_ATTRIBUTE_ABSTRACT) ? "abstract " : "",
                            (!(m.flags & METHOD_ATTRIBUTE_ABSTRACT) && (m.flags & METHOD_ATTRIBUTE_VIRTUAL)) ? "virtual " : "",
                            ret.c_str(), m.name.c_str());
                    if (!m.paramTypes.empty()) {
                        for (size_t i = 0; i < m.paramTypes.size(); i++)
                            fprintf(f, "%s%s arg%zu", i ? ", " : "", TypeName(ctx, m.paramTypes[i]).c_str(), i);
                    } else if (m.paramCount) {
                        for (uint8_t i = 0; i < m.paramCount; i++)
                            fprintf(f, "%sobject arg%u", i ? ", " : "", i);
                    }
                    fprintf(f, ") { }\n");
                }
            }
            fprintf(f, "}\n\n");
        }
    }
    fclose(f);
    Log("[+] wrote %s", path.c_str());
}

void EmitScriptJson(Context& ctx, const std::string& path) {
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "w") != 0 || !f) { Log("[!] cannot write %s", path.c_str()); return; }
    setvbuf(f, nullptr, _IOFBF, 1 << 22);

    fprintf(f, "{\n");
    fprintf(f, "  \"ModuleName\": \"GameAssembly.dll\",\n");
    fprintf(f, "  \"ImageBase\": \"0x%llX\",\n", ctx.gaBase);
    fprintf(f, "  \"BuildStamp\": \"0x%08X\",\n", ctx.gaTimeStamp);
    fprintf(f, "  \"AddressKind\": \"rva\",\n");
    fprintf(f, "  \"ScriptMethod\": [\n");
    bool first = true;
    for (const ClassDump& c : ctx.classes) {
        if (c.methods.empty()) continue;
        std::string cn = FullName(ctx, c);
        for (const MethodDump& m : c.methods) {
            if (!m.rva) continue;
            std::string sig = (m.returnType ? TypeName(ctx, m.returnType) : "void") + " " + cn + "." + m.name + "(";
            for (size_t i = 0; i < m.paramTypes.size(); i++)
                sig += (i ? ", " : "") + TypeName(ctx, m.paramTypes[i]);
            sig += ")";
            if (!first) fprintf(f, ",\n");
            first = false;
            fprintf(f, "    {\"Address\": %llu, \"Rva\": \"0x%llX\", \"Va\": \"0x%llX\", \"Name\": \"%s$$%s\", \"Signature\": \"%s\"}",
                    m.rva, m.rva, m.methodPtr,
                    JsonEsc(Sanitize(cn)).c_str(), JsonEsc(Sanitize(m.name)).c_str(), JsonEsc(sig).c_str());
        }
    }
    fprintf(f, "\n  ],\n");

    fprintf(f, "  \"ScriptMetadata\": [\n");
    first = true;
    for (const ClassDump& c : ctx.classes) {
        if (c.isGenericInst || !c.handle) continue;
        if (!ctx.InGA(c.handle)) continue;
        if (!first) fprintf(f, ",\n");
        first = false;
        fprintf(f, "    {\"Address\": %llu, \"Name\": \"%s_TypeDefinition\"}",
                c.handle - ctx.gaBase, JsonEsc(Sanitize(FullName(ctx, c))).c_str());
    }
    fprintf(f, "\n  ]\n}\n");
    fclose(f);
    Log("[+] wrote %s", path.c_str());
}

void EmitIl2CppHeader(Context& ctx, const std::string& path) {
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "w") != 0 || !f) return;
    const Layout& L = ctx.L;
    fprintf(f, "// IL2CPP runtime struct layout, measured live in GameAssembly.dll build %08X.\n",
            ctx.gaTimeStamp);
    fprintf(f, "// Field order can differ from stock IL2CPP; these are what this build uses.\n");
    fprintf(f, "// Re-generated on every dump - do not carry it across a game update.\n\n");
    fprintf(f, "#pragma pack(push, 1)\n\n");

    fprintf(f, "struct Il2CppType {\n  void*    data;      // +0x%02X\n  uint32_t bits;      // +0x%02X"
               " (ELEMENT_TYPE at +0x%02X, byref at bit %u)\n  uint32_t _pad;\n};\n\n",
            L.typ_data, L.typ_bits, L.typ_typeByte, L.typ_byrefBit);

    struct Ent { uint32_t off; const char* decl; uint32_t size; };
    auto emitStruct = [&](const char* name, std::vector<Ent> ents, uint32_t total) {
        std::sort(ents.begin(), ents.end(), [](const Ent& a, const Ent& b) { return a.off < b.off; });
        fprintf(f, "struct %s {\n", name);
        uint32_t at = 0; int gap = 0;
        for (const Ent& e : ents) {
            if (e.off < at) continue;
            if (e.off > at) fprintf(f, "  uint8_t  _gap%d[0x%X];\n", gap++, e.off - at);
            fprintf(f, "  %-46s // +0x%03X\n", e.decl, e.off);
            at = e.off + e.size;
        }
        if (total > at) fprintf(f, "  uint8_t  _gap%d[0x%X];\n", gap, total - at);
        fprintf(f, "};  // sizeof 0x%X\n\n", (std::max)(total, at));
    };

    emitStruct("Il2CppClass", {
        { L.cls_image,          "struct Il2CppImage* image;", 8 },
        { L.cls_self,           "struct Il2CppClass* klass;  // itself", 8 },
        { L.cls_namespaze,      "const char* namespaze;", 8 },
        { L.cls_byval,          "struct Il2CppType byval_arg;", L.typ_size },
        { L.cls_this,           "struct Il2CppType this_arg;", L.typ_size },
        { L.cls_declaring,      "struct Il2CppClass* declaringType;", 8 },
        { L.cls_handle,         "const void* typeMetadataHandle;", 8 },
        { L.cls_parent,         "struct Il2CppClass* parent;", 8 },
        { L.cls_methods,        "const struct MethodInfo** methods;", 8 },
        { L.cls_fields,         "struct FieldInfo* fields;", 8 },
        { L.cls_interfaces,     "struct Il2CppClass** implementedInterfaces;", 8 },
        { L.cls_name,           "const char* name;", 8 },
        { L.cls_staticFields,   "void* static_fields;", 8 },
        { L.cls_instanceSize,   "uint32_t instance_size;", 4 },
        { L.cls_flags,          "uint32_t flags;", 4 },
        { L.cls_methodCount,    "uint16_t method_count;", 2 },
        { L.cls_fieldCount,     "uint16_t field_count;", 2 },
        { L.cls_interfaceCount, "uint16_t interfaces_count;", 2 },
    }, 0);

    emitStruct("FieldInfo", {
        { L.fld_parent, "struct Il2CppClass* parent;", 8 },
        { L.fld_token,  "uint32_t token;", 4 },
        { L.fld_name,   "const char* name;", 8 },
        { L.fld_type,   "const struct Il2CppType* type;", 8 },
        { L.fld_offset, "int32_t offset;", 4 },
    }, L.fld_size);

    emitStruct("MethodInfo", {
        { L.mth_ptr,        "void* methodPointer;", 8 },
        { L.mth_klass,      "struct Il2CppClass* klass;", 8 },
        { L.mth_name,       "const char* name;", 8 },
        { L.mth_ret,        "const struct Il2CppType* return_type;", 8 },
        { L.mth_params,     "const struct Il2CppType** parameters;", 8 },
        { L.mth_handle,     "const void* methodMetadataHandle;", 8 },
        { L.mth_token,      "uint32_t token;", 4 },
        { L.mth_flags,      "uint16_t flags;", 2 },
        { L.mth_iflags,     "uint16_t iflags;", 2 },
        { L.mth_slot,       "uint16_t slot;", 2 },
        { L.mth_paramCount, L.mth_paramCountWidth == 1 ? "uint8_t  parameters_count;"
                                                       : "uint16_t parameters_count;", L.mth_paramCountWidth },
    }, L.mth_size);

    emitStruct("Il2CppImage", {
        { L.img_nameNoExt,     "const char* nameNoExt;", 8 },
        { L.img_name,          "const char* name;", 8 },
        { L.img_codeGenModule, "const struct Il2CppCodeGenModule* codeGenModule;", 8 },
    }, 0);

    emitStruct("Il2CppCodeGenModule", {
        { L.cgm_name,           "const char* moduleName;", 8 },
        { L.cgm_methodCount,    "uint32_t methodPointerCount;", 4 },
        { L.cgm_methodPointers, "void** methodPointers;", 8 },
    }, 0);

    emitStruct("Il2CppTypeDefinition", {
        { L.td_nameIndex,      "int32_t nameIndex;", 4 },
        { L.td_namespaceIndex, "int32_t namespaceIndex;", 4 },
        { L.td_flags,          "uint32_t flags;", 4 },
        { L.td_methodStart,    "int32_t methodStart;", 4 },
        { L.td_methodCount,    "uint16_t method_count;", 2 },
        { L.td_fieldCount,     "uint16_t field_count;", 2 },
        { L.td_token,          "uint32_t token;", 4 },
    }, L.td_size);

    fprintf(f, "// Il2CppMethodDefinition, stride 0x%X\n", L.md_size);
    fprintf(f, "//   nameIndex +0x%02X", L.md_nameIndex);
    if (L.md_token >= 0)      fprintf(f, "   token(u%d) +0x%02X", L.md_tokenWidth * 8, L.md_token);
    if (L.md_returnType >= 0) fprintf(f, "   returnType(u%d) +0x%02X", L.md_returnWidth * 8, L.md_returnType);
    if (L.md_flags >= 0)      fprintf(f, "\n//   flags +0x%02X", L.md_flags);
    if (L.md_slot >= 0)       fprintf(f, "   slot +0x%02X", L.md_slot);
    if (L.md_paramCount >= 0) fprintf(f, "   parameters_count +0x%02X", L.md_paramCount);
    fprintf(f, "\n\n#pragma pack(pop)\n");
    fclose(f);
    Log("[+] wrote %s", path.c_str());
}

void EmitLayoutJson(Context& ctx, const std::string& path) {
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "w") != 0 || !f) return;
    const Layout& L = ctx.L;
    fprintf(f, "{\n");
    fprintf(f, "  \"gameAssembly\": {\"base\": \"0x%llX\", \"size\": \"0x%llX\", \"timeDateStamp\": \"0x%08X\", \"checkSum\": \"0x%08X\"},\n",
            ctx.gaBase, ctx.gaSize, ctx.gaTimeStamp, ctx.gaCheckSum);
    fprintf(f, "  \"unityVersion\": \"%s\",\n", JsonEsc(ctx.unityVersion).c_str());
    fprintf(f, "  \"stringHeap\": {\"lo\": \"0x%llX\", \"hi\": \"0x%llX\", \"origin\": \"0x%llX\", \"regions\": %zu},\n",
            ctx.heapLo, ctx.heapHi, ctx.strBase, ctx.heapRanges.size());
    fprintf(f, "  \"methodDefinitionTable\": \"0x%llX\",\n", ctx.methodDefTable);
    fprintf(f, "  \"typesTable\": {\"address\": \"0x%llX\", \"count\": %u},\n", ctx.typesArray, ctx.typesCount);
    fprintf(f, "  \"Il2CppClass\": {\"image\": %u, \"self\": %u, \"namespaze\": %u, \"byval_arg\": %u,"
               " \"this_arg\": %u, \"declaringType\": %u, \"typeMetadataHandle\": %u, \"parent\": %u,"
               " \"methods\": %u, \"fields\": %u, \"implementedInterfaces\": %u, \"name\": %u,"
               " \"static_fields\": %u, \"instance_size\": %u, \"flags\": %u, \"method_count\": %u,"
               " \"field_count\": %u, \"interfaces_count\": %u},\n",
            L.cls_image, L.cls_self, L.cls_namespaze, L.cls_byval, L.cls_this, L.cls_declaring,
            L.cls_handle, L.cls_parent, L.cls_methods, L.cls_fields, L.cls_interfaces, L.cls_name,
            L.cls_staticFields, L.cls_instanceSize, L.cls_flags, L.cls_methodCount,
            L.cls_fieldCount, L.cls_interfaceCount);
    fprintf(f, "  \"Il2CppType\": {\"data\": %u, \"bits\": %u, \"typeByte\": %u, \"byrefBit\": %u, \"size\": %u},\n",
            L.typ_data, L.typ_bits, L.typ_typeByte, L.typ_byrefBit, L.typ_size);
    fprintf(f, "  \"Il2CppGenericClass\": {\"typeHandle\": %u, \"class_inst\": %u, \"cached_class\": %u},\n",
            L.gc_typeHandle, L.gc_classInst, L.gc_cachedClass);
    fprintf(f, "  \"FieldInfo\": {\"parent\": %u, \"token\": %u, \"name\": %u, \"type\": %u, \"offset\": %u, \"size\": %u},\n",
            L.fld_parent, L.fld_token, L.fld_name, L.fld_type, L.fld_offset, L.fld_size);
    fprintf(f, "  \"MethodInfo\": {\"methodPointer\": %u, \"klass\": %u, \"name\": %u, \"return_type\": %u,"
               " \"parameters\": %u, \"metadataHandle\": %u, \"token\": %u, \"flags\": %u, \"iflags\": %u,"
               " \"slot\": %u, \"parameters_count\": %u, \"size\": %u},\n",
            L.mth_ptr, L.mth_klass, L.mth_name, L.mth_ret, L.mth_params, L.mth_handle,
            L.mth_token, L.mth_flags, L.mth_iflags, L.mth_slot, L.mth_paramCount, L.mth_size);
    fprintf(f, "  \"Il2CppImage\": {\"nameNoExt\": %u, \"name\": %u, \"codeGenModule\": %u},\n",
            L.img_nameNoExt, L.img_name, L.img_codeGenModule);
    fprintf(f, "  \"Il2CppCodeGenModule\": {\"name\": %u, \"methodPointerCount\": %u, \"methodPointers\": %u},\n",
            L.cgm_name, L.cgm_methodCount, L.cgm_methodPointers);
    fprintf(f, "  \"Il2CppTypeDefinition\": {\"nameIndex\": %u, \"namespaceIndex\": %u, \"flags\": %u,"
               " \"methodStart\": %u, \"method_count\": %u, \"field_count\": %u, \"token\": %u, \"size\": %u},\n",
            L.td_nameIndex, L.td_namespaceIndex, L.td_flags, L.td_methodStart, L.td_methodCount,
            L.td_fieldCount, L.td_token, L.td_size);
    fprintf(f, "  \"Il2CppMethodDefinition\": {\"nameIndex\": %d, \"token\": %d, \"tokenWidth\": %d,"
               " \"returnType\": %d, \"returnWidth\": %d, \"flags\": %d, \"iflags\": %d, \"slot\": %d,"
               " \"parameters_count\": %d, \"size\": %u}\n",
            L.md_nameIndex, L.md_token, L.md_tokenWidth, L.md_returnType, L.md_returnWidth,
            L.md_flags, L.md_iflags, L.md_slot, L.md_paramCount, L.md_size);
    fprintf(f, "}\n");
    fclose(f);
    Log("[+] wrote %s", path.c_str());
}

void EmitHealthJson(Context& ctx, const std::string& path) {
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "w") != 0 || !f) return;

    int failedCritical = 0, failed = 0;
    for (const auto& r : ctx.fits) {
        if (r.fitted) continue;
        failed++;
        if (r.critical) failedCritical++;
    }
    double cross = ctx.metaCheckTotal ? 100.0 * ctx.metaCheckAgree / ctx.metaCheckTotal : -1.0;
    const char* verdict = failedCritical ? "broken" :
                          (failed || (cross >= 0 && cross < 99.0)) ? "degraded" : "ok";

    fprintf(f, "{\n");
    fprintf(f, "  \"verdict\": \"%s\",\n", verdict);
    fprintf(f, "  \"buildStamp\": \"0x%08X\",\n", ctx.gaTimeStamp);
    fprintf(f, "  \"unityVersion\": \"%s\",\n", JsonEsc(ctx.unityVersion).c_str());
    fprintf(f, "  \"failedFits\": %d,\n", failed);
    fprintf(f, "  \"failedCriticalFits\": %d,\n", failedCritical);
    fprintf(f, "  \"metadataCrossCheck\": {\"agree\": %d, \"checked\": %d, \"percent\": %.2f},\n",
            ctx.metaCheckAgree, ctx.metaCheckTotal, cross < 0 ? 0.0 : cross);
    fprintf(f, "  \"fits\": [\n");
    for (size_t i = 0; i < ctx.fits.size(); i++) {
        const FitRecord& r = ctx.fits[i];
        fprintf(f, "    {\"what\": \"%s\", \"value\": \"%s\", \"agree\": %d, \"of\": %d, \"fitted\": %s, \"critical\": %s}%s\n",
                JsonEsc(r.what).c_str(), JsonEsc(r.value).c_str(), r.agree, r.total,
                r.fitted ? "true" : "false", r.critical ? "true" : "false",
                i + 1 == ctx.fits.size() ? "" : ",");
    }
    fprintf(f, "  ]\n}\n");
    fclose(f);

    Log("");
    Log("=== fit health: %s ===", verdict);
    if (failed) {
        Log("    %d fit(s) fell back to a default%s:", failed, failedCritical ? " (INCLUDING CRITICAL ONES)" : "");
        for (const auto& r : ctx.fits)
            if (!r.fitted) Log("      %s %-34s %s", r.critical ? "!!" : "  ", r.what.c_str(), r.value.c_str());
    }
    if (cross >= 0) Log("    metadata cross-check %.1f%% (%d/%d)", cross, ctx.metaCheckAgree, ctx.metaCheckTotal);
    Log("[+] wrote %s", path.c_str());
}

void EmitSummary(Context& ctx, const std::string& path) {
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "w") != 0 || !f) return;
    size_t nm = 0, nf = 0, rva = 0, gen = 0;
    for (const auto& c : ctx.classes) {
        nm += c.methods.size(); nf += c.fields.size();
        if (c.isGenericInst) gen++;
        for (const auto& m : c.methods) if (m.rva) rva++;
    }
    fprintf(f, "combat-master-dumper summary\n");
    fprintf(f, "=============================\n");
    fprintf(f, "GameAssembly.dll   0x%llX (0x%llX bytes) build %08X\n", ctx.gaBase, ctx.gaSize, ctx.gaTimeStamp);
    if (!ctx.unityVersion.empty()) fprintf(f, "Unity              %s\n", ctx.unityVersion.c_str());
    fprintf(f, "string heap        0x%llX - 0x%llX (origin 0x%llX)\n", ctx.heapLo, ctx.heapHi, ctx.strBase);
    fprintf(f, "method def table   0x%llX%s\n", ctx.methodDefTable, ctx.methodDefTableValid ? "" : "  (not located)");
    fprintf(f, "assemblies         %zu\n", ctx.images.size());
    fprintf(f, "types              %zu (%zu generic instantiations)\n", ctx.classes.size(), gen);
    fprintf(f, "fields             %zu\n", nf);
    fprintf(f, "methods            %zu (%zu with a resolved RVA)\n", nm, rva);
    if (ctx.metaCheckTotal)
        fprintf(f, "cross-check        %.1f%% (%d/%d method names)\n\n",
                100.0 * ctx.metaCheckAgree / ctx.metaCheckTotal, ctx.metaCheckAgree, ctx.metaCheckTotal);
    else fprintf(f, "\n");

    fprintf(f, "per-assembly:\n");
    std::vector<const ImageDump*> v;
    for (const auto& im : ctx.images) v.push_back(&im);
    std::sort(v.begin(), v.end(), [](const ImageDump* a, const ImageDump* b) {
        return a->classIdx.size() > b->classIdx.size();
    });
    for (const ImageDump* im : v) {
        size_t m = 0;
        for (size_t i : im->classIdx) m += ctx.classes[i].methods.size();
        fprintf(f, "  %-52s %6zu types  %7zu methods  cgm=%s\n",
                im->name.c_str(), im->classIdx.size(), m, im->codeGenModule ? "yes" : "no");
    }
    fclose(f);
    Log("[+] wrote %s", path.c_str());
}

void EmitIdaScript(const std::string& path) {
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "w") != 0 || !f) return;
    static const char* PY =
"# Applies script.json to an IDA database of GameAssembly.dll.\n"
"# In IDA:  File > Script file...  ->  ida_apply.py\n"
"import json\n"
"import os\n"
"\n"
"import idaapi\n"
"import idc\n"
"import ida_funcs\n"
"import ida_name\n"
"import ida_kernwin\n"
"import ida_bytes\n"
"\n"
"\n"
"def main():\n"
"    path = ida_kernwin.ask_file(False, \"script.json\", \"Select script.json from the dumper\")\n"
"    if not path or not os.path.exists(path):\n"
"        return\n"
"\n"
"    with open(path, \"r\", encoding=\"utf-8\") as fh:\n"
"        data = json.load(fh)\n"
"\n"
"    base = idaapi.get_imagebase()\n"
"    methods = data.get(\"ScriptMethod\", [])\n"
"    metadata = data.get(\"ScriptMetadata\", [])\n"
"    print(\"[il2cpp] script.json: %d methods, %d type definitions\" % (len(methods), len(metadata)))\n"
"    print(\"[il2cpp] dumped from build %s, rebasing onto 0x%X\"\n"
"          % (data.get(\"BuildStamp\", \"?\"), base))\n"
"\n"
"    renamed = created = skipped = 0\n"
"    for m in methods:\n"
"        ea = base + m[\"Address\"]\n"
"        if not ida_bytes.is_loaded(ea):\n"
"            skipped += 1\n"
"            continue\n"
"        if ida_funcs.get_func(ea) is None:\n"
"            if ida_funcs.add_func(ea):\n"
"                created += 1\n"
"        if ida_name.set_name(ea, m[\"Name\"], ida_name.SN_NOWARN | ida_name.SN_FORCE):\n"
"            renamed += 1\n"
"        sig = m.get(\"Signature\")\n"
"        if sig:\n"
"            idc.set_func_cmt(ea, sig, True)\n"
"\n"
"    for t in metadata:\n"
"        ea = base + t[\"Address\"]\n"
"        if ida_bytes.is_loaded(ea):\n"
"            ida_name.set_name(ea, t[\"Name\"], ida_name.SN_NOWARN | ida_name.SN_FORCE)\n"
"\n"
"    print(\"[il2cpp] renamed %d, created %d functions, skipped %d (address not loaded)\"\n"
"          % (renamed, created, skipped))\n"
"    print(\"[il2cpp] done\")\n"
"\n"
"\n"
"main()\n";
    fputs(PY, f);
    fclose(f);
    Log("[+] wrote %s", path.c_str());
}
