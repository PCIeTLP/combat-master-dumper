# combat-master-dumper

An [Il2CppDumper](https://github.com/Perfare/Il2CppDumper)-style dump for Combat Master, whose
build ships no usable `global-metadata.dat`. It reads the runtime's own structures out of the
live process instead of parsing a metadata file.

Inject the DLL, wait ~15 seconds, get `dump.cs` and `script.json`.

```
40,160 types · 155 assemblies · 50,823 fields · 184,886 methods · 177,321 resolved RVAs
```

> **Built for Combat Master** (Steam, Unity 6000.3.19), and only tested there. Everything here
> is fitted at runtime rather than hardcoded, so it has a fair chance on other IL2CPP titles —
> but that is untested, and I make no claims about it. If you try it elsewhere, `health.json`
> will tell you honestly whether it worked.

## Why not just use Il2CppDumper

| It needs | Combat Master has |
|---|---|
| `global-metadata.dat` | Not there. The metadata folder only holds `Resources/`. |
| `il2cpp_*` exports | Blanked — 241 of 251 export slots have RVA `0`, in memory too. |
| The `0xFAB11BAF` metadata header | Loaded in pieces, with the header page decommitted. |
| Stock struct layouts | Shuffled. `Il2CppClass::name` is at `+0xA0`, not `+0x10`. |
| Strings to scan for | None. Sections are named things like `.m7pdd0`. |

## Surviving game updates

There are no offsets in this repo to update. All 45 of them are re-derived on every run by
searching for the offset that satisfies something the runtime has to be doing anyway:

- **`Il2CppClass`** is the only struct that points at itself *and* owns a member array whose
  records point back at it.
- **`name` vs `namespaze`** — both index the string blob; `name` is mostly unique values,
  `namespaze` repeats and is often empty.
- **`fields` + `FieldInfo::parent`** are fitted as a pair. The container is only right if the
  record back-references the class.
- **`typeMetadataHandle` + `nameIndex` + the string origin** — the correct triple is the one
  where `namePtr - nameIndex` is the same constant for every class.
- **`Il2CppType.byref`** — XOR `byval_arg` against `this_arg`; for value types the only bit
  that differs is byref.
- **`MethodInfo::flags`** — `RTSpecialName` is set for `.ctor` and `.cctor` and nothing else.
- **`slot`** is `0xFFFF` for exactly the non-virtual methods.
- **`methodPointer`** must equal `codeGenModule.methodPointers[token_rid - 1]`. Three code
  pointers in `MethodInfo` look plausible; only one passes this.
- **`Il2CppMethodDefinition` stride** is the gap between the metadata handles of two
  consecutive methods of one class.

Every fit is scored and written to `health.json`, and `dump.log` ends with `ok`, `degraded` or
`broken`. A critical failure also sets exit code 10, which lands in `DONE.txt`. The check that
matters most is the last line of the log: method names recovered through the metadata path are
compared against the same methods read from the live runtime. Below 100% means something
upstream is wrong.

This did get tested for real — the game updated mid-development and it re-derived everything
from scratch, including `declaringType`, which the previous version had hardcoded to the stock
`+0x50` when this build puts it at `+0x88`.

It still assumes the string blob is plaintext in memory, that `Il2CppClass` self-references and
keeps `name`/`namespaze` as `char*`, and that `MethodInfo` is reachable from
`Il2CppClass::methods`. Break any of those and it reports `broken` rather than guessing.

## Build

Visual Studio 2022 or newer with the C++ workload.

```
combat-master-dumper.slnx    (open in VS, Release | x64)
```

or, without opening the IDE:

```
build.bat
```

Both put `combat_master_dumper.dll` and `injector.exe` in `bin\`. Release builds carry no PDB
path or debug info.

## Use

Inject `combat_master_dumper.dll` with whatever you like. `injector.exe` is a plain
`LoadLibrary` loader included for convenience:

```
injector.exe --process CombatMaster.exe
injector.exe --pid 1234
injector.exe --process CombatMaster.exe --unload
```

Output goes to `%LOCALAPPDATA%\il2cpp_dump\`, and `DONE.txt` is written last. The DLL unloads
itself when it finishes, so it leaves nothing in the module list. Injected at startup it waits
for IL2CPP to finish initialising instead of failing.

Read from the target's environment:

| Variable | Effect |
|---|---|
| `IL2CPP_DUMP_OUT` | Output directory |
| `IL2CPP_DUMP_WAIT` | Seconds to wait for the runtime (default 30) |
| `IL2CPP_DUMP_MSGBOX=1` | Popup on completion (off by default; invisible under fullscreen) |

## Output

| File | What it is |
|---|---|
| `dump.cs` | Source listing: namespaces, base types, generic args, field offsets, RVA + VA. |
| `script.json` | Every method as `{Address, Rva, Va, Name, Signature}` plus type definitions. |
| `health.json` | Every fit and its agreement rate. Read this first if a dump looks wrong. |
| `il2cpp_structs.h` | The struct layout as measured in this build, ready for IDA's type editor. |
| `layout.json` | All fitted offsets, blob bounds, table addresses, build stamp. |
| `summary.txt` | Per-assembly counts. |
| `ida_apply.py` | IDA importer for `script.json`, written next to it. |
| `dump.log` | Full fit report. |

### IDA

Open `GameAssembly.dll`, then **File → Script file… → `ida_apply.py`** and point it at
`script.json`. Addresses are RVAs so they rebase onto whatever base the database uses. It
creates missing functions, renames them `Namespace_Class$$Method` and attaches the signature as
a comment.

### Reading game state

Field offsets come out directly, so you usually don't need IDA to find a struct. Statics also
get an absolute address via `Il2CppClass::static_fields`:

```csharp
// TypeDefIndex: 0x0, Il2CppClass 0x278D1AC9470, instance_size 0x298, static_fields 0x278A58D7270
public class PlayerRoot : PlayerEntityEventListener, IUpdatable, IFixedUpdatable
{
    public static PlayerRoot MyPlayer;                  // static_fields+0x8  = 0x278A58D7278
    public static readonly List<PlayerRoot> AllPlayers; // static_fields+0x18 = 0x278A58D7288
    private Transform _firstPersonPivot;                // 0x30
    private CameraController _cameraController;         // 0x48
    private PlayerMovement _playerMovement;             // 0xB0
}
```

Offsets are stable across launches. **Addresses are not** — `Il2CppClass` and `static_fields`
are heap allocations that move every run, so resolve the class at runtime instead of hardcoding
`0x278A58D7288`. RVAs in `script.json` are file-relative and do stay put.

## Checking a dump

RVAs and field offsets were verified against the on-disk `GameAssembly.dll` in IDA and against
live memory — identical in both, every one landing on a function start:

| Method | RVA | Bytes | Dump says |
|---|---|---|---|
| `String.get_Length` | `0x5425E0` | `8B 41 10 C3` | `_stringLength // 0x10` |
| `PlayerRoot.get_FirstPersonPivot` | `0x57F200` | `48 8B 41 30 C3` | `_firstPersonPivot // 0x30` |
| `PlayerRoot.get_CameraController` | `0x57ECC0` | `48 8B 41 48 C3` | `_cameraController // 0x48` |

If something looks off, check `health.json`:

- `ok` — everything fitted, cross-check 100%.
- `degraded` — a non-critical fit fell back. Usable, but not the field it names.
- `broken` — a load-bearing fit fell back. Start at the first failure; it usually causes the rest.
- cross-check below 100% — the method table, its stride, or the string origin is wrong even if
  the individual fits claim success.

Low agreement isn't automatically bad. `typeMetadataHandle` tops out near 43% because generic
instantiations don't have one, and `static_fields` near 25% because most classes have no
statics. The denominators are in `health.json`.

## Limitations

- Parameter *names* are `arg0, arg1, …`. Types are correct.
- Generic instantiations (22,667 of the 40,160 types) are found but left out of `dump.cs`,
  which lists source types.
- Generic parameters render as `T` / `TMethod`, and open generics keep their `` `1 `` suffix.
- No `DummyDll/` — that needs an ECMA-335 writer. `script.json` has everything one would need.
- String literals aren't dumped. That table is one of the pieces this build keeps out of reach,
  and nothing is faked in its place.

## Anti-cheat

The dump itself found `CodeStage.AntiCheat` in `Assembly-CSharp` — `InjectionDetector`,
`SpeedHackDetector`, `WallHackDetector`, `ObscuredCheatingDetector` and the `Obscured*` types.
Combat Master is online and injecting a DLL into a live match is detectable in principle. Dump
an offline or menu session.

This is a reverse-engineering tool. Use it on games you own, and don't take it into multiplayer.

## Measured layout

Output, not input — regenerated every run into `il2cpp_structs.h`.

```c
Il2CppClass                          FieldInfo (0x28)        MethodInfo (0x58)
  +0x000 Il2CppImage* image            +0x00 parent            +0x00 methodPointer
  +0x010 Il2CppClass* klass (self)     +0x08 token             +0x18 klass
  +0x018 const char* namespaze         +0x10 name              +0x20 name
  +0x020 Il2CppType byval_arg          +0x18 type              +0x28 return_type
  +0x030 Il2CppType this_arg           +0x20 offset            +0x30 Il2CppType** parameters
  +0x068 typeMetadataHandle                                    +0x38 metadataHandle
  +0x078 parent                      Il2CppTypeDefinition       +0x48 token
  +0x080 MethodInfo** methods          (0x4C)                  +0x4C flags / +0x4E iflags
  +0x088 declaringType                 +0x00 nameIndex         +0x50 slot
  +0x090 FieldInfo* fields             +0x04 namespaceIndex    +0x52 parameters_count (u8)
  +0x098 implementedInterfaces         +0x10 flags
  +0x0A0 const char* name              +0x18 methodStart     Il2CppMethodDefinition (0x1E)
  +0x0B8 void* static_fields           +0x34 method_count      +0x00 nameIndex
  +0x0F8 instance_size                 +0x38 field_count       +0x06 returnType (u16)
  +0x118 flags                         +0x48 token             +0x12 token_rid (u16)
  +0x120 method_count (u16)                                    +0x16 flags / +0x18 iflags
  +0x124 field_count  (u16)                                    +0x1A slot
  +0x12C interfaces_count (u16)                                +0x1C parameters_count
```

`Il2CppMethodDefinition` is 30 bytes and stores its token as a bare `u16` RID. Both are
non-standard, and both were measured rather than assumed.

## Layout

```
src/           the dumper
  dumper.h       types and the Layout struct
  sweep.h        chunked walk over committed memory
  core.cpp       memory access, string-blob detection, class discovery, type naming
  fit.cpp        every offset fit
  emit.cpp       all output files
  dllmain.cpp    entry point, build identity, self-unload
injector/      LoadLibrary loader
```

MIT.
