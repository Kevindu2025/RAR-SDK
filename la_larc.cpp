/*
 * la_larc.cpp - C wrapper exposing learnarc's LArc container format
 *              as rarsdk_LArc* C functions.
 *
 * Underlying implementation: include/learnarc/container.hpp.
 *
 * LArc (LA v1) format: little-endian, per-entry CRC32 header, optional
 * RAR5-style AES-256-CBC encryption with PBKDF2-HMAC-SHA256 KDF and
 * MAC-folder integrity check. A real container you can open in a hex
 * editor and study - see container.hpp for full format spec.
 *
 * API surface:
 *   Writer: Create -> AddFile/Data/Dir* -> Save -> Free
 *   Reader: Open -> List(cb) | ExtractAll -> Close
 */
#include "rarsdk.h"
#include "include/learnarc/container.hpp"
#include "include/learnarc/arcrypto.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <sys/stat.h>
#else
#include <sys/stat.h>
#endif

/* ---------- file I/O helpers ---------- */

static bool read_file_bytes(const wchar_t *path, std::vector<uint8_t> &out)
{
    out.clear();
#ifdef _WIN32
    FILE *f = _wfopen(path, L"rb");
#else
    char mb[4096]; size_t i = 0;
    while (path[i] && i + 1 < sizeof(mb)) mb[i] = (char)path[i++];
    mb[i] = 0;
    FILE *f = fopen(mb, "rb");
#endif
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return false; }
    out.resize((size_t)sz);
    if (sz > 0 && fread(out.data(), 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f); return false;
    }
    fclose(f);
    return true;
}

static bool write_file_bytes(const wchar_t *path, const std::vector<uint8_t> &data)
{
#ifdef _WIN32
    FILE *f = _wfopen(path, L"wb");
#else
    char mb[4096]; size_t i = 0;
    while (path[i] && i + 1 < sizeof(mb)) mb[i] = (char)path[i++];
    mb[i] = 0;
    FILE *f = fopen(mb, "wb");
#endif
    if (!f) return false;
    if (!data.empty() && fwrite(data.data(), 1, data.size(), f) != data.size()) {
        fclose(f); return false;
    }
    fclose(f);
    return true;
}

#ifdef _WIN32
static std::string wide_to_utf8(const wchar_t *w)
{
    if (!w) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    std::string s;
    if (n <= 0) return s;
    s.resize((size_t)n - 1);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, NULL, NULL);
    return s;
}

static std::wstring utf8_to_wide(const char *s)
{
    if (!s) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    std::wstring w;
    if (n <= 0) return w;
    w.resize((size_t)n - 1);
    MultiByteToWideChar(CP_UTF8, 0, s, -1, &w[0], n);
    return w;
}
#endif

/* ---------- writer handle ---------- */

struct rarsdk_larc_writer {
    std::vector<uint8_t> buf;
};

extern "C" {

rarsdk_larc_writer * RARCALL rarsdk_LArcWriterCreate(void)
{
    rarsdk_larc_writer *w = new rarsdk_larc_writer();
    learnarc::archive_init(w->buf);
    return w;
}

static int add_opts_from_params(unsigned int method, unsigned int kdfLg2,
                                 const char *password, int encrypt,
                                 learnarc::AddOptions *out)
{
    out->method = (int)method;
    out->ppmOrder = 6;
    out->encrypt = (encrypt != 0);
    if (kdfLg2 == 0) kdfLg2 = 15;
    if (kdfLg2 > 24) kdfLg2 = 24;
    out->kdfLg2 = kdfLg2;
    out->password = password;
    if (out->encrypt && (!password || !*password)) return RARSDK_E_PASSWORD;
    return RARSDK_OK;
}

int RARCALL rarsdk_LArcWriterAddFile(rarsdk_larc_writer *w,
                                       const wchar_t *srcPath,
                                       const char *arcName,
                                       unsigned int method, unsigned int kdfLg2,
                                       const char *password, int encrypt)
{
    if (!w || !srcPath || !arcName) return RARSDK_E_PARAM;
    std::vector<uint8_t> data;
    if (!read_file_bytes(srcPath, data)) return RARSDK_E_IO;

    learnarc::AddOptions opt;
    int rc = add_opts_from_params(method, kdfLg2, password, encrypt, &opt);
    if (rc != RARSDK_OK) return rc;

    std::string err;
    rc = learnarc::add_one(w->buf, std::string(arcName),
                            data.data(), data.size(), opt, &err);
    return rc ? RARSDK_E_INTERNAL : RARSDK_OK;
}

int RARCALL rarsdk_LArcWriterAddData(rarsdk_larc_writer *w,
                                       const char *arcName,
                                       const void *data, size_t size,
                                       unsigned int method, unsigned int kdfLg2,
                                       const char *password, int encrypt)
{
    if (!w || !arcName) return RARSDK_E_PARAM;
    if (!data && size) return RARSDK_E_PARAM;

    learnarc::AddOptions opt;
    int rc = add_opts_from_params(method, kdfLg2, password, encrypt, &opt);
    if (rc != RARSDK_OK) return rc;

    std::string err;
    rc = learnarc::add_one(w->buf, std::string(arcName),
                            static_cast<const uint8_t*>(data), size, opt, &err);
    return rc ? RARSDK_E_INTERNAL : RARSDK_OK;
}

int RARCALL rarsdk_LArcWriterAddDir(rarsdk_larc_writer *w, const char *dirName)
{
    if (!w || !dirName) return RARSDK_E_PARAM;
    learnarc::AddOptions opt;
    opt.method = 0;       /* store, no encryption for dir entries */
    opt.encrypt = false;
    opt.kdfLg2 = 0;
    opt.password = nullptr;
    std::vector<uint8_t> empty;
    std::string err;
    int rc = learnarc::add_one(w->buf, std::string(dirName),
                                empty.data(), 0, opt, &err);
    return rc ? RARSDK_E_INTERNAL : RARSDK_OK;
}

int RARCALL rarsdk_LArcWriterSave(rarsdk_larc_writer *w, const wchar_t *path)
{
    if (!w || !path) return RARSDK_E_PARAM;
    learnarc::archive_finish(w->buf);
    return write_file_bytes(path, w->buf) ? RARSDK_OK : RARSDK_E_WRITE;
}

void RARCALL rarsdk_LArcWriterFree(rarsdk_larc_writer *w)
{
    delete w;
}

/* ---------- reader handle ---------- */

struct rarsdk_larc_reader {
    std::vector<uint8_t> buf;
};

rarsdk_larc_reader * RARCALL rarsdk_LArcReaderOpen(const wchar_t *path)
{
    if (!path) return NULL;
    rarsdk_larc_reader *r = new rarsdk_larc_reader();
    if (!read_file_bytes(path, r->buf)) { delete r; return NULL; }
    return r;
}

void RARCALL rarsdk_LArcReaderClose(rarsdk_larc_reader *r)
{
    delete r;
}

int RARCALL rarsdk_LArcReaderList(rarsdk_larc_reader *r,
                                   rarsdk_LArcEntryCallback cb, void *user)
{
    if (!r || !cb) return RARSDK_E_PARAM;
    std::string err;
    int rc = learnarc::iterate(r->buf.data(), r->buf.size(),
        [cb, user](const learnarc::EntryInfo &e, const uint8_t *, size_t) {
            return cb(user, e.name.c_str(),
                       (unsigned int)e.method, e.encrypted ? 1 : 0,
                       (unsigned long long)e.origLen,
                       (unsigned long long)e.compLen);
        }, &err);
    return rc ? RARSDK_E_FORMAT : RARSDK_OK;
}

static int extract_one(const learnarc::EntryInfo &e, const uint8_t *comp, size_t compLen,
                        const char *password, const std::wstring &outDir, int isWin,
                        std::string &err)
{
    std::vector<uint8_t> out;
    int rc = learnarc::extract_entry(e, comp, compLen, password, out, &err);
    if (rc) return rc;
#ifdef _WIN32
    std::wstring full = outDir;
    if (!full.empty() && full.back() != L'\\' && full.back() != L'/') full += L'\\';
    std::wstring aname = utf8_to_wide(e.name.c_str());
    full += aname;
    FILE *f = _wfopen(full.c_str(), L"wb");
    (void)isWin;
#else
    std::string full;
    {
        char buf[4096]; size_t i = 0;
        while (outDir[i] && i + 1 < sizeof(buf)) buf[i] = (char)outDir[i++];
        buf[i] = 0;
        full = buf;
    }
    if (!full.empty() && full.back() != '/' && full.back() != '\\') full += '/';
    full += e.name;
    FILE *f = fopen(full.c_str(), "wb");
#endif
    if (!f) { err = "cannot create " + e.name; return RARSDK_E_WRITE; }
    if (!out.empty() && fwrite(out.data(), 1, out.size(), f) != out.size()) {
        fclose(f); err = "write failed " + e.name; return RARSDK_E_WRITE;
    }
    fclose(f);
    return 0;
}

int RARCALL rarsdk_LArcReaderExtractAll(rarsdk_larc_reader *r,
                                         const wchar_t *outDir,
                                         const char *password)
{
    if (!r) return RARSDK_E_PARAM;

#ifdef _WIN32
    /* ensure output directory exists */
    if (outDir && *outDir) CreateDirectoryW(outDir, NULL);
    std::wstring wdir = outDir ? outDir : L".";
#else
    std::wstring wdir;
    if (outDir) {
        char mb[4096]; size_t i = 0;
        while (outDir[i] && i + 1 < sizeof(mb)) mb[i] = (char)outDir[i++];
        mb[i] = 0;
        mkdir(mb, 0755);
    }
#endif

    int rcCount = 0;
    std::string err;
    int rc = learnarc::iterate(r->buf.data(), r->buf.size(),
        [&](const learnarc::EntryInfo &e, const uint8_t *d, size_t dl) {
            int xr = extract_one(e, d, dl, password, wdir, 1, err);
            if (xr == 0) { rcCount++; return 0; }
            if (xr == RARSDK_E_PASSWORD) return xr;     /* abort iteration */
            /* non-fatal per-entry failure (CRC mismatch etc): keep going */
            return 0;
        }, &err);
    if (rc < 0) return rc;
    return rcCount;
}

}  /* extern "C" */
