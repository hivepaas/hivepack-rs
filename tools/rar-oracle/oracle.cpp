// tools/rar-oracle: UnRAR 7.3.2's own reading of RAR archives, for comparing
// hivepack-rar with it. Built by scripts/testdata.py with UnRAR's sources,
// as UnRAR's library is built (-DRARDLL), and linked with them.
//
// It reads requests from standard input, one a line, and answers each on one
// line:
//
//   list <enable_broken> <hex>
//
// opens the archive (its bytes in hex), as IsArchive opens it, then reads every header as Archive::ReadHeader reads them,
// printing what UnRAR keeps of each: the header's fields, the archive's
// state, and the exit code at the end.
//
//   test <hex> [<dictionary limit>]
//
// goes through the archive as UnRAR tests one, with CmdExtract's own
// ExtractCurrentFile, printing after each header how much data it gave out,
// its FNV-1a hash, whether its hash failed, where the archive is and the exit
// code.
//
// hivepack-rar answers the same requests in crates/rar/tests/oracle.rs, and
// the answers are compared as text.
//
//   hash <type> <chunk> <hex>
//
// hashes the bytes in chunks of that size with UnRAR's DataHash, HASH_RAR14,
// HASH_CRC32 or HASH_BLAKE2 by number, and prints the hash.
//
// UnRAR's license, whose source this program is built with:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.

#include <clocale>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <string>
#include <vector>

// For RarVM's memory and Unpack::ApplyFilter, compared by themselves.
#define private public
#include "rar.hpp"
#undef private

#ifdef __linux__
#include <sys/mman.h>
#endif
#include <unistd.h>

static std::string out;

static void put(const char *key, unsigned long long value) {
  char buf[64];
  snprintf(buf, sizeof(buf), " %s=%llx", key, value);
  out += buf;
}

static void put_bytes(const char *key, const byte *data, size_t size) {
  out += " ";
  out += key;
  out += "=";
  if (size == 0)
    out += "-";
  for (size_t i = 0; i < size; i++) {
    char buf[3];
    snprintf(buf, sizeof(buf), "%02x", data[i]);
    out += buf;
  }
}

static void put_wide(const char *key, const std::wstring &s) {
  out += " ";
  out += key;
  out += "=";
  if (s.empty())
    out += "-";
  for (size_t i = 0; i < s.size(); i++) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%s%x", i ? "." : "", (unsigned)(uint32_t)s[i]);
    out += buf;
  }
}

static void put_time(const char *key, RarTime &t) {
  put(key, t.GetUnixNS());
}

static void put_base(BaseBlock &b) {
  put("crc", b.HeadCRC);
  put("type", (unsigned)b.HeaderType);
  put("flags", b.Flags);
  put("size", b.HeadSize);
  put("skip", b.SkipIfUnknown);
}

// What UnRAR does not set is left out: FileHeader::Reset clears only some
// fields, and the others keep what an earlier header or the heap left.
static void put_file(FileHeader &h, RARFORMAT format) {
  if (format == RARFMT14) {
    // RAR 1.4 has no header CRC.
    put("type", (unsigned)h.HeaderType);
    put("flags", h.Flags);
    put("size", h.HeadSize);
  } else
    put_base(h);
  if (format != RARFMT50)
    put("ds", h.DataSize);
  put("host", h.HostOS);
  put("unpver", h.UnpVer);
  put("method", h.Method);
  put("attr", h.FileAttr);
  put_wide("name", h.FileName);
  put_bytes("subdata", h.SubData.data(), h.SubData.size());
  put_time("mtime", h.mtime);
  put_time("ctime", h.ctime);
  put_time("atime", h.atime);
  put("packsize", (unsigned long long)h.PackSize);
  put("unpsize", (unsigned long long)h.UnpSize);
  if (format == RARFMT50)
    put("maxsize", (unsigned long long)h.MaxSize);
  // CRC32 and Digest are a union: only what the type says is meaningful.
  put("hashtype", h.FileHash.Type);
  if (h.FileHash.Type == HASH_RAR14 || h.FileHash.Type == HASH_CRC32)
    put("crc32", h.FileHash.CRC32);
  if (h.FileHash.Type == HASH_BLAKE2)
    put_bytes("digest", h.FileHash.Digest, BLAKE2_DIGEST_SIZE);
  if (format == RARFMT50)
    put("fileflags", h.FileFlags);
  put("splitbefore", h.SplitBefore);
  put("splitafter", h.SplitAfter);
  put("unknownsize", h.UnknownUnpSize);
  put("encrypted", h.Encrypted);
  put("cryptmethod", h.CryptMethod);
  put("saltset", h.SaltSet);
  if (h.SaltSet)
    put_bytes("salt", h.Salt, format == RARFMT50 ? SIZE_SALT50 : SIZE_SALT30);
  if (h.CryptMethod == CRYPT_RAR50)
    put_bytes("initv", h.InitV, sizeof(h.InitV));
  put("usepswcheck", h.UsePswCheck);
  if (h.UsePswCheck)
    put_bytes("pswcheck", h.PswCheck, sizeof(h.PswCheck));
  put("usehashkey", h.UseHashKey);
  put("lg2count", h.Lg2Count);
  put("solid", h.Solid);
  put("dir", h.Dir);
  put("commentinheader", h.CommentInHeader);
  put("version", h.Version);
  put("winsize", h.WinSize);
  put("inherited", h.Inherited);
  put("largefile", h.LargeFile);
  put("subblock", h.SubBlock);
  put("hstype", h.HSType);
  put("redirtype", h.RedirType);
  if (h.RedirType != FSREDIR_NONE)
    put_wide("redirname", h.RedirName);
  put("dirtarget", h.DirTarget);
  put("ownerset", h.UnixOwnerSet);
  if (h.UnixOwnerSet) {
    put("ownernumeric", h.UnixOwnerNumeric);
    put("groupnumeric", h.UnixGroupNumeric);
    put_bytes("owner", (const byte *)h.UnixOwnerName, strlen(h.UnixOwnerName));
    put_bytes("group", (const byte *)h.UnixGroupName, strlen(h.UnixGroupName));
    if (h.UnixOwnerNumeric)
      put("ownerid", (unsigned long long)h.UnixOwnerID);
    if (h.UnixGroupNumeric)
      put("groupid", (unsigned long long)h.UnixGroupID);
  }
}

// What the archive says of itself, after IsArchive and after each header.
static void put_state(Archive &a) {
  put("format", a.Format);
  put("solid", a.Solid);
  put("volume", a.Volume);
  put("maincomment", a.MainComment);
  put("locked", a.Locked);
  put("signed", a.Signed);
  put("firstvolume", a.FirstVolume);
  put("newnumbering", a.NewNumbering);
  put("protected", a.Protected);
  put("encrypted", a.Encrypted);
  put("sfx", a.SFXSize);
  put("broken", a.BrokenHeader);
  put("faileddecryption", a.FailedHeaderDecryption);
  put("volnumber", a.VolNumber);
  put("recovery", (unsigned long long)(long long)a.GetRecoveryPercent());
  put("cur", (unsigned long long)a.CurBlockPos);
  put("next", (unsigned long long)a.NextBlockPos);
  put("headertype", (unsigned)a.GetHeaderType());
}

// Each header by its kind, for the kinds the archive's format reads: RAR 5
// reads main, file, service, encryption and end headers, RAR 1.5 to 4.x no
// encryption header but its old comment, recovery and service headers. Any
// other kind is its ShortBlock.
static int kind_read(Archive &a) {
  int type = a.GetHeaderType();
  switch (type) {
    case HEAD_MAIN: case HEAD_FILE: case HEAD_SERVICE: case HEAD_ENDARC:
      return type;
    case HEAD_CRYPT:
      return a.Format == RARFMT50 ? type : -1;
    case HEAD3_CMT: case HEAD3_PROTECT: case HEAD3_OLDSERVICE:
      return a.Format == RARFMT15 ? type : -1;
  }
  return -1;
}

static void put_header(Archive &a) {
  switch (kind_read(a)) {
    case HEAD_MAIN: {
      MainHeader &m = a.MainHead;
      put_base(m);
      put("highposav", m.HighPosAV);
      put("posav", m.PosAV);
      put("commentinheader", m.CommentInHeader);
      put("packcomment", m.PackComment);
      put("locator", m.Locator);
      put("qopen", m.QOpenOffset);
      put("rr", m.RROffset);
      put_wide("origname", m.OrigName);
      put_time("origtime", m.OrigTime);
      break;
    }
    case HEAD_FILE:
      put_file(a.FileHead, a.Format);
      break;
    case HEAD_SERVICE:
      put_file(a.SubHead, a.Format);
      break;
    case HEAD_CRYPT:
      put_base(a.CryptHead);
      put("usepswcheck", a.CryptHead.UsePswCheck);
      put("lg2count", a.CryptHead.Lg2Count);
      put_bytes("salt", a.CryptHead.Salt, sizeof(a.CryptHead.Salt));
      if (a.CryptHead.UsePswCheck)
        put_bytes("pswcheck", a.CryptHead.PswCheck, sizeof(a.CryptHead.PswCheck));
      break;
    case HEAD_ENDARC:
      put_base(a.EndArcHead);
      put("nextvolume", a.EndArcHead.NextVolume);
      put("datacrc", a.EndArcHead.DataCRC);
      put("revspace", a.EndArcHead.RevSpace);
      put("storevolnumber", a.EndArcHead.StoreVolNumber);
      if (a.EndArcHead.DataCRC)
        put("arcdatacrc", a.EndArcHead.ArcDataCRC);
      if (a.EndArcHead.StoreVolNumber)
        put("endvolnumber", a.EndArcHead.VolNumber);
      break;
    case HEAD3_CMT:
      put_base(a.CommHead);
      put("unpsize", a.CommHead.UnpSize);
      put("unpver", a.CommHead.UnpVer);
      put("method", a.CommHead.Method);
      put("commcrc", a.CommHead.CommCRC);
      break;
    case HEAD3_PROTECT:
      put_base(a.ProtectHead);
      put("ds", a.ProtectHead.DataSize);
      put("version", a.ProtectHead.Version);
      put("recsectors", a.ProtectHead.RecSectors);
      put("totalblocks", a.ProtectHead.TotalBlocks);
      put_bytes("mark", a.ProtectHead.Mark, sizeof(a.ProtectHead.Mark));
      break;
    case HEAD3_OLDSERVICE:
      put_base(a.SubBlockHead);
      put("ds", a.SubBlockHead.DataSize);
      put("subtype", a.SubBlockHead.SubType);
      put("level", a.SubBlockHead.Level);
      if (a.SubBlockHead.SubType == NTACL_HEAD) {
        put("unpsize", a.EAHead.UnpSize);
        put("unpver", a.EAHead.UnpVer);
        put("method", a.EAHead.Method);
        put("subcrc", a.EAHead.EACRC);
      }
      if (a.SubBlockHead.SubType == STREAM_HEAD) {
        put("unpsize", a.StreamHead.UnpSize);
        put("unpver", a.StreamHead.UnpVer);
        put("method", a.StreamHead.Method);
        put("subcrc", a.StreamHead.StreamCRC);
        put_bytes("streamname", (const byte *)a.StreamHead.StreamName.data(),
                  a.StreamHead.StreamName.size());
      }
      break;
    default:
      put_base(a.ShortBlock);
      break;
  }
}

static std::vector<byte> unhex(const char *hex) {
  std::vector<byte> data;
  for (size_t i = 0; hex[i] && hex[i + 1]; i += 2) {
    char pair[3] = {hex[i], hex[i + 1], 0};
    data.push_back((byte)strtoul(pair, NULL, 16));
  }
  return data;
}

// The archive, in memory and not in /tmp: how far a damaged header can seek
// depends on the file system. ext4 refuses to seek past 16 TiB, which UnRAR
// takes for a fatal error, and tmpfs and this file do not. Only Linux's answers
// are compared, so elsewhere a file will do. -1 if it failed.
static int archive_file(const char *hex, char *path, size_t path_size) {
  std::vector<byte> data = unhex(hex);
#ifdef __linux__
  int fd = memfd_create("rar-oracle", 0);
  snprintf(path, path_size, "/proc/self/fd/%d", fd);
#else
  snprintf(path, path_size, "/tmp/rar-oracle-XXXXXX");
  int fd = mkstemp(path);
#endif
  if (fd < 0 || (data.size() && write(fd, data.data(), data.size()) != (ssize_t)data.size())) {
    printf("error writing\n");
    return -1;
  }
  return fd;
}

static void close_archive_file(int fd, const char *path) {
  close(fd);
#ifndef __linux__
  unlink(path);
#endif
}

// The password of the request being answered, in hex: UTF-8.
static std::wstring request_password;

static void set_password(CommandData &Cmd) {
  if (!request_password.empty())
    Cmd.Password.Set(request_password.c_str());
}

static std::wstring password_from_hex(const char *hex) {
  std::vector<byte> bytes = unhex(hex);
  std::string utf((const char *)bytes.data(), bytes.size());
  std::wstring wide;
  UtfToWide(utf.c_str(), wide);
  return wide;
}

static void do_list(int enable_broken, const char *hex) {
  char path[64];
  int fd = archive_file(hex, path, sizeof(path));
  if (fd < 0)
    return;

  out = "list";
  ErrHandler.Clean();
  CommandData Cmd;
  set_password(Cmd);
  try {
    Archive Arc(&Cmd);
    std::string narrow(path);
    std::wstring wide(narrow.begin(), narrow.end());
    if (!Arc.Open(wide)) {
      out += " notopened";
    } else {
      bool ok = Arc.IsArchive(enable_broken != 0);
      out += ok ? " archive" : " notarchive";
      put_state(Arc);
      // IsArchive sets HeadSize only when it finds a signature.
      put_bytes("mark", Arc.MarkHead.Mark, ok ? Arc.MarkHead.HeadSize : 0);
      if (ok) {
        size_t size;
        while ((size = Arc.ReadHeader()) != 0) {
          out += " |";
          put("read", size);
          put_state(Arc);
          put_header(Arc);
          Arc.SeekToNext();
        }
        out += " | end";
        put_state(Arc);
      }
    }
  } catch (RAR_EXIT code) {
    put("thrown", code);
  } catch (std::bad_alloc &) {
    out += " badalloc";
  }
  put("exit", ErrHandler.GetErrorCode());
  close_archive_file(fd, path);
  printf("%s\n", out.c_str());
}

static unsigned long long data_size, data_fnv;

// All an entry's data comes here, and nobody allows anything: no password, no
// next volume, no larger dictionary.
// Zeros in what UnRAR allocates with new[]: damaged data can have RAR 3's
// filters read their memory (RarVM::Mem) before it is written, and an answer
// must not depend on what was on the heap. The port's memory starts as zeros.
void *operator new[](size_t size) {
  void *memory = calloc(size ? size : 1, 1);
  if (memory == NULL)
    throw std::bad_alloc();
  return memory;
}
void operator delete[](void *memory) noexcept { free(memory); }
void operator delete[](void *memory, size_t) noexcept { free(memory); }

static int CALLBACK test_callback(UINT msg, LPARAM, LPARAM p1, LPARAM p2) {
  // A next volume that is there is fine, and one that is not stays that way.
  if ((msg == UCM_CHANGEVOLUME || msg == UCM_CHANGEVOLUMEW) && p2 == RAR_VOL_NOTIFY)
    return 1;
  if (msg != UCM_PROCESSDATA)
    return -1;
  const byte *data = (const byte *)p1;
  for (size_t i = 0; i < (size_t)p2; i++) {
    data_fnv ^= data[i];
    data_fnv *= 0x100000001b3ULL;
  }
  data_size += (size_t)p2;
  return 1;
}

// The volumes of a `testvol` request, each a name and its bytes: the archive is
// the first, among real files so that UnRAR finds the next ones by their names.
static std::vector<std::pair<std::string, std::string>> request_volumes;

static std::string write_volumes() {
  // In memory where there is any, as for the memfd of a lone archive: ext4
  // refuses a seek past 16 TiB, which a damaged size asks for, and UnRAR takes
  // that for a fatal error, which says something of the file system only.
  char shared[] = "/dev/shm/rar-oracle-XXXXXX";
  char temporary[] = "/tmp/rar-oracle-XXXXXX";
  char *dir = mkdtemp(shared);
  if (!dir)
    dir = mkdtemp(temporary);
  if (!dir)
    return "";
  for (auto &volume : request_volumes) {
    std::vector<byte> data = unhex(volume.second.c_str());
    std::string name = std::string(dir) + "/" + volume.first;
    FILE *f = fopen(name.c_str(), "wb");
    if (!f)
      return "";
    if (!data.empty())
      fwrite(data.data(), 1, data.size(), f);
    fclose(f);
  }
  return dir;
}

static void remove_volumes(const std::string &dir) {
  for (auto &volume : request_volumes)
    unlink((dir + "/" + volume.first).c_str());
  rmdir(dir.c_str());
}

static void do_test(const char *hex, unsigned long long limit) {
  char path[256];
  std::string volume_dir;
  int fd = -1;
  if (request_volumes.empty()) {
    fd = archive_file(hex, path, sizeof(path));
    if (fd < 0)
      return;
  } else {
    volume_dir = write_volumes();
    snprintf(path, sizeof(path), "%s/%s", volume_dir.c_str(), request_volumes[0].first.c_str());
  }

  out = "test";
  ErrHandler.Clean();
  // What RAROpenArchiveEx and ProcessFile set for testing, QuickOpen on, as there.
  // Recursing is the one difference: with "*" as the only mask and no recursing,
  // UnRAR stops after a first file whose name is that very "*", taking it for
  // all that was asked for, which says nothing of reading the archive.
  CommandData Cmd;
  Cmd.FileArgs.AddString(L"*");
  Cmd.Overwrite = OVERWRITE_ALL;
  Cmd.VersionControl = 1;
  Cmd.Recurse = RECURSE_ALWAYS;
  Cmd.DllOpMode = RAR_TEST;
  Cmd.Command = L"T";
  Cmd.Test = true;
  if (limit != 0)
    Cmd.WinSizeLimit = Cmd.WinSize = limit;
  set_password(Cmd);
  try {
    Archive Arc(&Cmd);
    CmdExtract Extract(&Cmd);
    std::string narrow(path);
    std::wstring wide(narrow.begin(), narrow.end());
    if (!Arc.Open(wide)) {
      out += " notopened";
    } else if (!Arc.IsArchive(true)) {
      out += " notarchive";
    } else {
      out += " archive";
      // Only now: IsArchive reads on past an encrypted main header if there is
      // a callback that could give a password, and this one gives none.
      Cmd.Callback = test_callback;
      Extract.ExtractArchiveInit(Arc);
      while (true) {
        size_t size = Arc.ReadHeader();
        out += " |";
        put("read", size);
        put("headertype", (unsigned)Arc.GetHeaderType());
        put("cur", (unsigned long long)Arc.CurBlockPos);
        put("next", (unsigned long long)Arc.NextBlockPos);
        // What UnRAR's mask refuses is passed over on both sides: "*" does not match a name that
        // starts with "*" and goes on, as match() takes that "*" for a plain
        // character. That is choosing files, and hivepack-rar has no masks.
        if (size != 0 && Arc.GetHeaderType() == HEAD_FILE) {
          FileHeader &h = Arc.FileHead;
          if (!Cmd.IsProcessFile(h, NULL, MATCH_WILDSUBPATH, false, NULL)) {
            out += " later";
            Arc.SeekToNext();
            continue;
          }
        }
        data_size = 0;
        data_fnv = 0xcbf29ce484222325ULL;
        bool repeat = false;
        // As ProcessFile does: what this entry alone did, which the exit code
        // does not say once it has a worse one.
        Cmd.DllError = 0;
        bool go = Extract.ExtractCurrentFile(Arc, size, repeat);
        put("data", data_size);
        put("fnv", data_fnv);
        put("baddata", Cmd.DllError == ERAR_BAD_DATA);
        put("nopassword", Cmd.DllError == ERAR_MISSING_PASSWORD);
        put("badpassword", Cmd.DllError == ERAR_BAD_PASSWORD);
        put("novolume", Cmd.DllError == ERAR_EOPEN);
        put("pos", (unsigned long long)Arc.Tell());
        put("broken", Arc.BrokenHeader);
        put("code", ErrHandler.GetErrorCode());
        if (!go)
          break;
      }
    }
  } catch (RAR_EXIT code) {
    put("thrown", code);
  } catch (std::bad_alloc &) {
    out += " badalloc";
  }
  put("exit", ErrHandler.GetErrorCode());
  if (volume_dir.empty())
    close_archive_file(fd, path);
  else
    remove_volumes(volume_dir);
  printf("%s\n", out.c_str());
}

// Archive::GetComment after opening, as what comes before the first entry.
static void do_comment(const char *hex) {
  char path[64];
  int fd = archive_file(hex, path, sizeof(path));
  if (fd < 0)
    return;
  out = "comment";
  ErrHandler.Clean();
  CommandData Cmd;
  set_password(Cmd);
  try {
    Archive Arc(&Cmd);
    std::string narrow(path);
    std::wstring wide(narrow.begin(), narrow.end());
    if (!Arc.Open(wide)) {
      out += " notopened";
    } else if (!Arc.IsArchive(true)) {
      out += " notarchive";
    } else {
      std::wstring comment;
      if (Arc.GetComment(comment)) {
        out += " comment=";
        for (wchar c : comment) {
          char buf[16];
          snprintf(buf, sizeof(buf), "%x,", (unsigned)c);
          out += buf;
        }
      } else {
        out += " none";
      }
      put("pos", (unsigned long long)Arc.Tell());
    }
  } catch (RAR_EXIT code) {
    put("thrown", code);
  } catch (std::bad_alloc &) {
    out += " badalloc";
  }
  put("exit", ErrHandler.GetErrorCode());
  close_archive_file(fd, path);
  printf("%s\n", out.c_str());
}

static void do_hash(int type, size_t chunk, const char *hex) {
  std::vector<byte> data = unhex(hex);
  DataHash hash;
  hash.Init((HASH_TYPE)type, 1);
  for (size_t at = 0; at < data.size(); at += chunk)
    hash.Update(data.data() + at, Min(chunk, data.size() - at));
  HashValue value;
  hash.Result(&value);
  out = "hash";
  if (type == HASH_BLAKE2)
    put_bytes("digest", value.Digest, sizeof(value.Digest));
  else
    put("crc32", value.CRC32);
  printf("%s\n", out.c_str());
}

static unsigned long long fnv(const byte *data, size_t size) {
  unsigned long long h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < size; i++) {
    h ^= data[i];
    h *= 0x100000001b3ULL;
  }
  return h;
}

// RarVM::Execute of one standard filter over these bytes.
static void do_filter3(int kind, uint r0, uint r1, uint r4, uint r6, const char *hex) {
  static const VM_StandardFilters kinds[] = {VMSF_NONE, VMSF_E8, VMSF_E8E9, VMSF_ITANIUM,
                                             VMSF_RGB, VMSF_AUDIO, VMSF_DELTA};
  std::vector<byte> data = unhex(hex);
  RarVM vm;
  vm.Init();
  vm.SetMemory(0, data.data(), data.size());
  VM_PreparedProgram prg;
  prg.Type = kinds[kind];
  memset(prg.InitR, 0, sizeof(prg.InitR));
  prg.InitR[0] = r0;
  prg.InitR[1] = r1;
  prg.InitR[4] = r4;
  prg.InitR[6] = r6;
  vm.Execute(&prg);
  out = "filter3";
  put("size", prg.FilteredDataSize);
  put("at", prg.FilteredData - vm.Mem);
  put("fnv", fnv(prg.FilteredData, prg.FilteredDataSize));
  put("mem", fnv(vm.Mem, VM_MEMSIZE + 4));
  printf("%s\n", out.c_str());
}

// Unpack::ApplyFilter over these bytes, with so much already written.
static void do_filter5(int kind, int channels, uint written, const char *hex) {
  std::vector<byte> data = unhex(hex);
  static ComprDataIO io;
  static Unpack unpack(&io);
  unpack.WrittenFileSize = written;
  UnpackFilter filter;
  filter.Type = (byte)kind;
  filter.Channels = (byte)channels;
  filter.NextWindow = false;
  filter.BlockStart = 0;
  filter.BlockLength = (uint)data.size();
  byte *output = unpack.ApplyFilter(data.data(), (uint)data.size(), &filter);
  out = "filter5";
  if (output == NULL)
    out += " none";
  else
    put("fnv", fnv(output, data.size()));
  printf("%s\n", out.c_str());
}

// ModelPPM by itself. A stream that is not one stops the model within a few
// hundred symbols, and the archives at hand are too short to fill its least
// memory, 1 MiB, so this gives it `heap` bytes as if that had been asked for and
// starts it again where it stops: what no stream at hand reaches is its memory
// filling, the gluing of free blocks and its restarts.
static void do_ppm(unsigned long long count, uint heap, const char *hex) {
  std::vector<byte> data = unhex(hex);
  size_t at = 0;
  static ComprDataIO io;
  static Unpack *unpack = NULL;
  delete unpack;
  unpack = new Unpack(&io);
  const size_t chunk = 0x4000;
  auto feed = [&]() {
    if (io.UnpackFromMemorySize == 0 && at < data.size()) {
      size_t size = Min(chunk, data.size() - at);
      io.UnpackFromMemory = true;
      io.UnpackFromMemoryAddr = data.data() + at;
      io.UnpackFromMemorySize = size;
      at += size;
    }
  };
  feed();
  unpack->UnpReadBuf30();
  feed();
  int esc = 2;
  out = "ppm";
  if (!unpack->PPM.DecodeInit(unpack, esc)) {
    out += " noinit";
  } else {
    int order = unpack->PPM.MaxOrder;
    unpack->PPM.SubAlloc.SubAllocatorSize = heap;
    unpack->PPM.StartModelRare(order);
    unsigned long long done = 0, h = 0xcbf29ce484222325ULL, restarts = 0;
    while (done < count) {
      feed();
      int ch = unpack->PPM.DecodeChar();
      if (ch == -1) {
        if (at >= data.size())
          break;
        // The coder too, as a block's start does: UnRAR never goes on with one
        // that has failed, and would divide by zero.
        feed();
        unpack->PPM.Coder.InitDecoder(unpack);
        unpack->PPM.StartModelRare(order);
        restarts++;
        continue;
      }
      h ^= (byte)ch;
      h *= 0x100000001b3ULL;
      done++;
    }
    put("symbols", done);
    put("restarts", restarts);
    put("fnv", h);
  }
  // The bytes are about to go: nothing is left to read from them.
  io.UnpackFromMemorySize = 0;
  printf("%s\n", out.c_str());
}

// CryptData by itself: SetCryptKeys with this password, salt ("-" for none)
// and count, then DecryptBlock of this data in chunks of this size.
static void do_crypt(int method, const char *password, const char *salt_hex, const char *initv_hex,
                     uint lg2, size_t chunk, const char *hex) {
  static CryptData crypt;
  std::vector<byte> data = unhex(hex);
  std::vector<byte> salt = unhex(salt_hex);
  std::vector<byte> initv = unhex(initv_hex);
  salt.resize(SIZE_SALT50);
  initv.resize(SIZE_INITV);
  SecPassword pwd;
  pwd.Set(password_from_hex(password).c_str());
  byte hash_key[SHA256_DIGEST_SIZE] = {0};
  byte psw_check[SIZE_PSWCHECK] = {0};
  bool set = crypt.SetCryptKeys(false, (CRYPT_METHOD)method, &pwd,
                                strcmp(salt_hex, "-") == 0 ? NULL : salt.data(), initv.data(), lg2,
                                hash_key, psw_check);
  out = "crypt";
  put("set", set);
  if (set) {
    put_bytes("hashkey", hash_key, sizeof(hash_key));
    put_bytes("pswcheck", psw_check, sizeof(psw_check));
    data.resize(data.size() + CRYPT_BLOCK_SIZE);
    size_t size = data.size() - CRYPT_BLOCK_SIZE;
    for (size_t at = 0; at < size; at += chunk)
      crypt.DecryptBlock(data.data() + at, Min(chunk, size - at));
    put_bytes("data", data.data(), size);
  }
  printf("%s\n", out.c_str());
}

int main() {
  setenv("TZ", "UTC", 1);
  tzset();
  setlocale(LC_ALL, "C.UTF-8");

  std::string line;
  int c;
  while (true) {
    line.clear();
    while ((c = getchar()) != EOF && c != '\n')
      line += (char)c;
    if (c == EOF && line.empty())
      break;
    char *words[512];
    int count = 0;
    for (char *w = strtok(&line[0], " "); w && count < 512; w = strtok(NULL, " "))
      words[count++] = w;
    if (count >= 5 && count % 2 == 1 && strcmp(words[0], "testvol") == 0) {
      // testvol <password> <limit> <name> <bytes> ...
      if (strcmp(words[1], "-") != 0)
        request_password = password_from_hex(words[1]);
      for (int i = 3; i + 1 < count; i += 2)
        request_volumes.emplace_back(words[i], words[i + 1]);
      do_test("", strtoull(words[2], NULL, 10));
      request_volumes.clear();
      request_password.clear();
    } else if (count == 3 && strcmp(words[0], "comment") == 0) {
      if (strcmp(words[1], "-") != 0)
        request_password = password_from_hex(words[1]);
      do_comment(words[2]);
      request_password.clear();
    } else if (count == 8 && strcmp(words[0], "crypt") == 0)
      do_crypt(atoi(words[1]), words[2], words[3], words[4], (uint)atoi(words[5]),
               strtoul(words[6], NULL, 10), words[7]);
    else if ((count == 3 || count == 4) && strcmp(words[0], "testpw") == 0) {
      request_password = password_from_hex(words[1]);
      do_test(words[2], count == 4 ? strtoull(words[3], NULL, 10) : 0);
      request_password.clear();
    } else if (count == 4 && strcmp(words[0], "listpw") == 0) {
      request_password = password_from_hex(words[1]);
      do_list(atoi(words[2]), words[3]);
      request_password.clear();
    } else if (count == 3 && strcmp(words[0], "list") == 0)
      do_list(atoi(words[1]), words[2]);
    else if (count == 2 && strcmp(words[0], "list") == 0)
      do_list(atoi(words[1]), "");
    else if (count == 3 && strcmp(words[0], "test") == 0)
      do_test(words[1], strtoull(words[2], NULL, 10));
    else if (count == 2 && strcmp(words[0], "test") == 0)
      do_test(words[1], 0);
    else if (count == 1 && strcmp(words[0], "test") == 0)
      do_test("", 0);
    else if (count == 4 && strcmp(words[0], "hash") == 0)
      do_hash(atoi(words[1]), strtoul(words[2], NULL, 10), words[3]);
    else if (count == 4 && strcmp(words[0], "ppm") == 0)
      do_ppm(strtoull(words[1], NULL, 10), (uint)strtoul(words[2], NULL, 10), words[3]);
    else if (count == 7 && strcmp(words[0], "filter3") == 0)
      do_filter3(atoi(words[1]), (uint)strtoul(words[2], NULL, 10), (uint)strtoul(words[3], NULL, 10),
                 (uint)strtoul(words[4], NULL, 10), (uint)strtoul(words[5], NULL, 10), words[6]);
    else if (count == 5 && strcmp(words[0], "filter5") == 0)
      do_filter5(atoi(words[1]), atoi(words[2]), (uint)strtoul(words[3], NULL, 10), words[4]);
    else
      printf("unknown request\n");
    fflush(stdout);
  }
  return 0;
}
