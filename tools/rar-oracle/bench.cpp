// tools/rar-oracle/bench.cpp: UnRAR 7.3.2's speed, for tools/rar-bench. Built by
// scripts/testdata.py with UnRAR's sources, as its library is built, without
// RAR_SMP, so on one thread, as hivepack-rar runs.
//
// It reads requests from standard input, one a line, and answers each on one line:
//
//   test PATH
//   testpw PATH
//
// tests the archive at PATH with UnRAR's own interface, as `unrar t` does, the
// second with the password `hivepack`, and answers with the nanoseconds it took
// and the bytes it gave out, or `error`.
#include "rar.hpp"
#include "dll.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>

static int CALLBACK count(UINT msg, LPARAM user, LPARAM, LPARAM size) {
  if (msg == UCM_PROCESSDATA)
    *reinterpret_cast<unsigned long long *>(user) += static_cast<unsigned long long>(size);
  // No passwords, no other volumes, and no dictionary over the limit, which the
  // port leaves out by default too.
  return msg == UCM_NEEDPASSWORD || msg == UCM_NEEDPASSWORDW || msg == UCM_CHANGEVOLUME ||
                 msg == UCM_CHANGEVOLUMEW || msg == UCM_LARGEDICT
             ? -1
             : 1;
}

static bool test(char *path, bool password, unsigned long long *bytes) {
  RAROpenArchiveDataEx data;
  memset(&data, 0, sizeof data);
  data.ArcName = path;
  data.OpenMode = RAR_OM_EXTRACT;
  HANDLE arc = RAROpenArchiveEx(&data);
  if (arc == NULL || data.OpenResult != ERAR_SUCCESS)
    return false;
  RARSetCallback(arc, count, reinterpret_cast<LPARAM>(bytes));
  static char secret[] = "hivepack";
  if (password)
    RARSetPassword(arc, secret);
  RARHeaderDataEx header;
  memset(&header, 0, sizeof header);
  bool ok = true;
  for (;;) {
    int status = RARReadHeaderEx(arc, &header);
    if (status == ERAR_END_ARCHIVE)
      break;
    if (status != ERAR_SUCCESS || RARProcessFile(arc, RAR_TEST, NULL, NULL) != ERAR_SUCCESS) {
      ok = false;
      break;
    }
  }
  RARCloseArchive(arc);
  return ok;
}

int main() {
  static char line[1 << 16];
  while (fgets(line, sizeof line, stdin) != NULL) {
    line[strcspn(line, "\r\n")] = 0;
    bool password = strncmp(line, "testpw ", 7) == 0;
    if (!password && strncmp(line, "test ", 5) != 0) {
      puts("error");
    } else {
      unsigned long long bytes = 0;
      auto start = std::chrono::steady_clock::now();
      bool ok = test(line + (password ? 7 : 5), password, &bytes);
      auto took = std::chrono::steady_clock::now() - start;
      if (ok)
        printf("%lld %llu\n",
               static_cast<long long>(std::chrono::duration_cast<std::chrono::nanoseconds>(took).count()),
               bytes);
      else
        puts("error");
    }
    fflush(stdout);
  }
  return 0;
}
