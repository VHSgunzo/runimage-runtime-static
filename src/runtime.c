#ident "Runtime for RunImage by VHSgunzo, vhsgunzo.github.io"
#define RUNTIME_VERSION "0.4.9"

#define _GNU_SOURCE

#include "squashfuse.h"
#include <squashfs_fs.h>
#include <nonstd.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <wait.h>
#include <fnmatch.h>

#include "hexlify.c"
#include "notify.c"
#include "elf.c"
#include "picohash.h"

#ifndef ENABLE_DLOPEN
#define ENABLE_DLOPEN
#endif

/* Exit status to use when launching an AppImage fails.
 * For applications that assign meanings to exit status codes (e.g. rsync),
 * we avoid "cluttering" pre-defined exit status codes by using 127 which
 * is known to alias an application exit status and also known as launcher
 * error, see SYSTEM(3POSIX).
 */
#define EXIT_EXECERROR  127     /* Execution error exit status.  */

//#include "notify.c"
extern int notify(char *title, char *body, int timeout);
struct stat st;

static ssize_t fs_offset; // The offset at which a filesystem image is expected = end of this ELF

static void die(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_EXECERROR);
}

/* Check whether directory is writable */
bool is_writable_directory(char* str) {
    if(access(str, W_OK) == 0) {
        return true;
    } else {
        return false;
    }
}

bool startsWith(const char *pre, const char *str)
{
    size_t lenpre = strlen(pre),
    lenstr = strlen(str);
    return lenstr < lenpre ? false : strncmp(pre, str, lenpre) == 0;
}

/* Fill in a stat structure. Does not set st_ino */
sqfs_err private_sqfs_stat(sqfs *fs, sqfs_inode *inode, struct stat *st) {
        sqfs_err err = SQFS_OK;
        uid_t id;

        memset(st, 0, sizeof(*st));
        st->st_mode = inode->base.mode;
        st->st_nlink = inode->nlink;
        st->st_mtime = st->st_ctime = st->st_atime = inode->base.mtime;

        if (S_ISREG(st->st_mode)) {
                /* FIXME: do symlinks, dirs, etc have a size? */
                st->st_size = inode->xtra.reg.file_size;
                st->st_blocks = st->st_size / 512;
        } else if (S_ISBLK(st->st_mode) || S_ISCHR(st->st_mode)) {
                st->st_rdev = sqfs_makedev(inode->xtra.dev.major,
                        inode->xtra.dev.minor);
        } else if (S_ISLNK(st->st_mode)) {
                st->st_size = inode->xtra.symlink_size;
        }

        st->st_blksize = fs->sb.block_size; /* seriously? */

        err = sqfs_id_get(fs, inode->base.uid, &id);
        if (err)
                return err;
        st->st_uid = id;
        err = sqfs_id_get(fs, inode->base.guid, &id);
        st->st_gid = id;
        if (err)
                return err;

        return SQFS_OK;
}

/* ================= End ELF parsing */

extern int fusefs_main(int argc, char *argv[], void (*mounted) (void));
// extern void ext2_quit(void);

static pid_t fuse_pid;
static int keepalive_pipe[2];

static void *
write_pipe_thread (void *arg)
{
    char c[32];
    int res;
    //  sprintf(stderr, "Called write_pipe_thread");
    memset (c, 'x', sizeof (c));
    while (1) {
        /* Write until we block, on broken pipe, exit */
        res = write (keepalive_pipe[1], c, sizeof (c));
        if (res == -1) {
            kill (fuse_pid, SIGTERM);
            break;
        }
    }
    return NULL;
}

void
fuse_mounted (void)
{
    pthread_t thread;
    fuse_pid = getpid();
    pthread_create(&thread, NULL, write_pipe_thread, keepalive_pipe);
}

char* getArg(int argc, char *argv[],char chr)
{
    int i;
    for (i=1; i<argc; ++i)
        if ((argv[i][0]=='-') && (argv[i][1]==chr))
            return &(argv[i][2]);
    return NULL;
}

int mkdir_p(const char *path, mode_t mode) {
    char *tmp = strdup(path);
    char *p = tmp;
    int ret = 0;

    if (tmp == NULL) {
        return -1;
    }

    // Check if the path length exceeds PATH_MAX
    if (strlen(path) >= PATH_MAX) {
        free(tmp);
        errno = ENAMETOOLONG;
        return -1;
    }

    // Use 0755 as the default mode if none is provided
    if (mode == 0) { mode = 0755 ; }

    do {
        p = strchr(p + 1, '/');
        if (p) {
            *p = '\0';
        }
        if (mkdir(tmp, mode) != 0) {
            if (errno != EEXIST) {
                ret = errno;
                break;
            }
        }
        if (p) {
            *p = '/';
        }
    } while (p);

    free(tmp);

    return (ret);
}

void
print_help(const char *runimage_path)
{
    // TODO: "--runtime-list                 List content from embedded filesystem image\n"
    fprintf(stderr,
        "Runtime for RunImage v%s by VHSgunzo\n"
        "   Runtime options:\n\n"
        "     --runtime-extract [<pattern>]  Extract content from embedded filesystem image\n"
        "                                     If pattern is passed, only extract matching files\n"
        "     --runtime-extract-and-run      Run the RunImage afer extraction without\n"
        "                                     using FUSE\n"
        "     --runtime-help                 Print this help\n"
        "     --runtime-mount                Mount embedded filesystem image and print\n"
        "                                     mount point and wait for kill with Ctrl-C\n"
        "     --runtime-offset               Print byte offset to start of embedded\n"
        "                                     filesystem image\n"
        "     --runtime-portable-home        Create a portable home folder to use as $HOME\n"
        "     --runtime-portable-config      Create a portable config folder to use as\n"
        "                                     $XDG_CONFIG_HOME\n"
        "     --runtime-version              Print version of Runtime\n"
        "\n"
        "Portable home:\n"
        "\n"
        "  If you would like the application contained inside this RunImage to store its\n"
        "  data alongside this RunImage rather than in your home directory, then you can\n"
        "  place a directory named\n"
        "\n"
        "  %s.home\n"
        "\n"
        "  Or you can invoke this RunImage with the --runtime-portable-home option,\n"
        "  which will create this directory for you. As long as the directory exists\n"
        "  and is neither moved nor renamed, the application contained inside this\n"
        "  RunImage to store its data in this directory rather than in your home\n"
        "  directory\n"
    , RUNTIME_VERSION, runimage_path);
}

void
portable_option(const char *arg, const char *runimage_path, const char *name)
{
    char option[32];
    sprintf(option, "runtime-portable-%s", name);

    if (arg && strcmp(arg, option)==0) {
        char portable_dir[PATH_MAX];
        char fullpath[PATH_MAX];

        ssize_t length = readlink(runimage_path, fullpath, sizeof(fullpath));
        if (length < 0) {
            fprintf(stderr, "Error getting realpath for %s\n", runimage_path);
            exit(EXIT_FAILURE);
        }
        fullpath[length] = '\0';

        sprintf(portable_dir, "%s.%s", fullpath, name);
        if (!mkdir(portable_dir, S_IRWXU))
            fprintf(stderr, "Portable %s directory created at %s\n", name, portable_dir);
        else
            fprintf(stderr, "Error creating portable %s directory at %s: %s\n", name, portable_dir, strerror(errno));

        exit(0);
    }
}

bool extract_appimage(const char* const runimage_path, const char* const _prefix, const char* const _pattern, const bool overwrite, const bool verbose) {
    sqfs_err err = SQFS_OK;
    sqfs_traverse trv;
    sqfs fs;
    char prefixed_path_to_extract[1024];

    // local copy we can modify safely
    // allocate 1 more byte than we would need so we can add a trailing slash if there is none yet
    char* prefix = malloc(strlen(_prefix) + 2);
    strcpy(prefix, _prefix);

    // sanitize prefix
    if (prefix[strlen(prefix) - 1] != '/')
        strcat(prefix, "/");

    if (access(prefix, F_OK) == -1) {
        if (mkdir_p(prefix, 0700) == -1) {
            perror("mkdir_p error");
            return false;
        }
    }

    if ((err = sqfs_open_image(&fs, runimage_path, (size_t) fs_offset))) {
        fprintf(stderr, "Failed to open squashfs image\n");
        return false;
    };

    // track duplicate inodes for hardlinks
    char** created_inode = calloc(fs.sb.inodes, sizeof(char*));
    if (created_inode == NULL) {
        fprintf(stderr, "Failed allocating memory to track hardlinks\n");
        return false;
    }

    if ((err = sqfs_traverse_open(&trv, &fs, sqfs_inode_root(&fs)))) {
        fprintf(stderr, "sqfs_traverse_open error\n");
        free(created_inode);
        return false;
    }

    bool rv = true;

    while (sqfs_traverse_next(&trv, &err)) {
        if (!trv.dir_end) {
            if (_pattern == NULL || fnmatch(_pattern, trv.path, FNM_FILE_NAME | FNM_LEADING_DIR) == 0) {
                // fprintf(stderr, "trv.path: %s\n", trv.path);
                // fprintf(stderr, "sqfs_inode_id: %lu\n", trv.entry.inode);
                sqfs_inode inode;
                if (sqfs_inode_get(&fs, &inode, trv.entry.inode)) {
                    fprintf(stderr, "sqfs_inode_get error\n");
                    rv = false;
                    break;
                }
                // fprintf(stderr, "inode.base.inode_type: %i\n", inode.base.inode_type);
                // fprintf(stderr, "inode.xtra.reg.file_size: %lu\n", inode.xtra.reg.file_size);
                strcpy(prefixed_path_to_extract, "");
                strcat(strcat(prefixed_path_to_extract, prefix), trv.path);

                if (verbose)
                    fprintf(stdout, "%s\n", prefixed_path_to_extract);

                if (inode.base.inode_type == SQUASHFS_DIR_TYPE || inode.base.inode_type == SQUASHFS_LDIR_TYPE) {
                    // fprintf(stderr, "inode.xtra.dir.parent_inode: %ui\n", inode.xtra.dir.parent_inode);
                    // fprintf(stderr, "mkdir_p: %s/\n", prefixed_path_to_extract);
                    if (access(prefixed_path_to_extract, F_OK) == -1) {
                        if (mkdir_p(prefixed_path_to_extract, 0) == -1) {
                            perror("mkdir_p error");
                            rv = false;
                            break;
                        }
                    }
                } else if (inode.base.inode_type == SQUASHFS_REG_TYPE || inode.base.inode_type == SQUASHFS_LREG_TYPE) {
                    // if we've already created this inode, then this is a hardlink
                    char* existing_path_for_inode = created_inode[inode.base.inode_number - 1];
                    if (existing_path_for_inode != NULL) {
                        unlink(prefixed_path_to_extract);
                        if (link(existing_path_for_inode, prefixed_path_to_extract) == -1) {
                            fprintf(stderr, "Couldn't create hardlink from \"%s\" to \"%s\": %s\n",
                                prefixed_path_to_extract, existing_path_for_inode, strerror(errno));
                            rv = false;
                            break;
                        } else {
                            continue;
                        }
                    } else {
                        struct stat st;
                        if (!overwrite && stat(prefixed_path_to_extract, &st) == 0 && st.st_size == inode.xtra.reg.file_size) {
                            fprintf(stderr, "File exists and file size matches, skipping\n");
                            continue;
                        }

                        // track the path we extract to for this inode, so that we can `link` if this inode is found again
                        created_inode[inode.base.inode_number - 1] = strdup(prefixed_path_to_extract);
                        // fprintf(stderr, "Extract to: %s\n", prefixed_path_to_extract);
                        if (private_sqfs_stat(&fs, &inode, &st) != 0)
                            die("private_sqfs_stat error");

                        // create parent dir
                        char* p = strrchr(prefixed_path_to_extract, '/');
                        if (p) {
                            // set an \0 to end the split the string
                            *p = '\0';
                            mkdir_p(prefixed_path_to_extract, 0);

                            // restore dir seprator
                            *p = '/';
                        }

                        // Read the file in chunks
                        off_t bytes_already_read = 0;
                        sqfs_off_t bytes_at_a_time = 64 * 1024;
                        FILE* f;
                        f = fopen(prefixed_path_to_extract, "w+");
                        if (f == NULL) {
                            perror("fopen error");
                            rv = false;
                            break;
                        }
                        while (bytes_already_read < inode.xtra.reg.file_size) {
                            char buf[bytes_at_a_time];
                            if (sqfs_read_range(&fs, &inode, (sqfs_off_t) bytes_already_read, &bytes_at_a_time, buf)) {
                                perror("sqfs_read_range error");
                                rv = false;
                                break;
                            }
                            // fwrite(buf, 1, bytes_at_a_time, stdout);
                            fwrite(buf, 1, bytes_at_a_time, f);
                            bytes_already_read = bytes_already_read + bytes_at_a_time;
                        }
                        fclose(f);
                        chmod(prefixed_path_to_extract, st.st_mode);
                        if (!rv)
                            break;
                    }
                } else if (inode.base.inode_type == SQUASHFS_SYMLINK_TYPE || inode.base.inode_type == SQUASHFS_LSYMLINK_TYPE) {
                    size_t size;
                    sqfs_readlink(&fs, &inode, NULL, &size);
                    char buf[size];
                    int ret = sqfs_readlink(&fs, &inode, buf, &size);
                    if (ret != 0) {
                        perror("symlink error");
                        rv = false;
                        break;
                    }
                    // fprintf(stderr, "Symlink: %s to %s \n", prefixed_path_to_extract, buf);
                    unlink(prefixed_path_to_extract);
                    ret = symlink(buf, prefixed_path_to_extract);
                    if (ret != 0)
                        fprintf(stderr, "WARNING: could not create symlink\n");
                } else {
                    fprintf(stderr, "TODO: Implement inode.base.inode_type %i\n", inode.base.inode_type);
                }
                // fprintf(stderr, "\n");

                if (!rv)
                    break;
            }
        }
    }
    for (int i = 0; i < fs.sb.inodes; i++) {
        free(created_inode[i]);
    }
    free(created_inode);

    if (err != SQFS_OK) {
        fprintf(stderr, "sqfs_traverse_next error\n");
        rv = false;
    }
    sqfs_traverse_close(&trv);
    sqfs_fd_close(fs.fd);

    return rv;
}

int rm_recursive_callback(const char* path, const struct stat* stat, const int type, struct FTW* ftw) {
    (void) stat;
    (void) ftw;

    switch (type) {
        case FTW_NS:
        case FTW_DNR:
            fprintf(stderr, "%s: ftw error: %s\n",
                path, strerror(errno));
            return 1;

        case FTW_D:
            // ignore directories at first, will be handled by FTW_DP
            break;

        case FTW_F:
        case FTW_SL:
        case FTW_SLN:
            if (remove(path) != 0) {
                fprintf(stderr, "Failed to remove %s: %s\n", path, strerror(errno));
                return false;
            }
            break;


        case FTW_DP:
            if (rmdir(path) != 0) {
                fprintf(stderr, "Failed to remove directory %s: %s\n", path, strerror(errno));
                return false;
            }
            break;

        default:
            fprintf(stderr, "Unexpected fts_info\n");
            return 1;
    }

    return 0;
};

bool rm_recursive(const char* const path) {
    // FTW_DEPTH: perform depth-first search to make sure files are deleted before the containing directories
    // FTW_MOUNT: prevent deletion of files on other mounted filesystems
    // FTW_PHYS: do not follow symlinks, but report symlinks as such; this way, the symlink targets, which might point
    //           to locations outside path will not be deleted accidentally (attackers might abuse this)
    int rv = nftw(path, &rm_recursive_callback, 0, FTW_DEPTH | FTW_MOUNT | FTW_PHYS);

    return rv == 0;
}

void
build_mount_point(char* mount_dir, const char* const argv0, char const* const temp_base, const size_t templen) {
    const size_t maxnamelen = 6;

    // when running for another AppImage, we should use that for building the mountpoint name instead
    char* target_appimage = getenv("TARGET_APPIMAGE");

    char* path_basename;
    if (target_appimage != NULL) {
        path_basename = basename(target_appimage);
    } else {
        path_basename = basename(argv0);
    }

    size_t namelen = strlen(path_basename);
    // limit length of tempdir name
    if (namelen > maxnamelen) {
        namelen = maxnamelen;
    }

    strcpy(mount_dir, temp_base);
    strncpy(mount_dir + templen, "/", 1);
    strncpy(mount_dir + templen + 1, path_basename, namelen);
    strncpy(mount_dir + templen + 1 + namelen, "XXXXXX", 6);
    mount_dir[templen + 1 + namelen + 6] = 0; // null terminate destination
}

int main(int argc, char *argv[]) {
    char runimage_path[PATH_MAX];
    char argv0_path[PATH_MAX];
    char * arg;

    /* We might want to operate on a target appimage rather than this file itself,
     * e.g., for appimaged which must not run untrusted code from random AppImages.
     * This variable is intended for use by e.g., appimaged and is subject to
     * change any time. Do not rely on it being present. We might even limit this
     * functionality specifically for builds used by appimaged.
     */
    if (getenv("TARGET_APPIMAGE") == NULL) {
        strcpy(runimage_path, "/proc/self/exe");
        strcpy(argv0_path, argv[0]);
    } else {
        strcpy(runimage_path, getenv("TARGET_APPIMAGE"));
        strcpy(argv0_path, getenv("TARGET_APPIMAGE"));

#ifdef ENABLE_SETPROCTITLE
        // load libbsd dynamically to change proc title
        // this is an optional feature, therefore we don't hard require it
        void* libbsd = dlopen("libbsd.so", RTLD_NOW);

        if (libbsd != NULL) {
            // clear error state
            dlerror();

            // try to load the two required symbols
            void (*setproctitle_init)(int, char**, char**) = dlsym(libbsd, "setproctitle_init");

            char* error;

            if ((error = dlerror()) == NULL) {
                void (*setproctitle)(const char*, char*) = dlsym(libbsd, "setproctitle");

                if (dlerror() == NULL) {
                    char buffer[1024];
                    strcpy(buffer, getenv("TARGET_APPIMAGE"));
                    for (int i = 1; i < argc; i++) {
                        strcat(buffer, " ");
                        strcat(buffer, argv[i]);
                    }

                    (*setproctitle_init)(argc, argv, environ);
                    (*setproctitle)("%s", buffer);
                }
            }

            dlclose(libbsd);
        }
#endif
    }

    // temporary directories are required in a few places
    // therefore we implement the detection of the temp base dir at the top of the code to avoid redundancy
    char temp_base[PATH_MAX] = P_tmpdir;

    {
        const char* const TMPDIR = getenv("TMPDIR");
        if (TMPDIR != NULL)
            strcpy(temp_base, getenv("TMPDIR"));
    }

    char reuiddir[13];
    sprintf(reuiddir, "%s/.r%u", temp_base, geteuid());
    sprintf(temp_base, "%s/mnt", reuiddir);

    fs_offset = appimage_get_elf_size(runimage_path);
    char sfs_offset[snprintf(NULL, 0, "%lu", fs_offset)];
    sprintf(sfs_offset, "%lu", fs_offset);

    // error check
    if (fs_offset < 0) {
        fprintf(stderr, "Failed to get fs offset for %s\n", runimage_path);
        exit(EXIT_EXECERROR);
    }

    arg=getArg(argc,argv,'-');

    /* Print the help and then exit */
    if(arg && strcmp(arg,"runtime-help")==0) {
        char fullpath[PATH_MAX];

        ssize_t length = readlink(runimage_path, fullpath, sizeof(fullpath));
        if (length < 0) {
            fprintf(stderr, "Error getting realpath for %s\n", runimage_path);
            exit(EXIT_EXECERROR);
        }
        fullpath[length] = '\0';

        print_help(fullpath);
        exit(0);
    }

    /* Just print the offset and then exit */
    if(arg && strcmp(arg,"runtime-offset")==0) {
        printf("%lu\n", fs_offset);
        exit(0);
    }

    arg=getArg(argc,argv,'-');

    /* extract the AppImage */
    if(arg && strcmp(arg,"runtime-extract")==0) {
        char* pattern;

        // default use case: use standard prefix
        if (argc == 2) {
            pattern = NULL;
        } else if (argc == 3) {
            pattern = argv[2];
        } else {
            fprintf(stderr, "Unexpected argument count: %d\n", argc - 1);
            fprintf(stderr, "Usage: %s --runtime-extract [<prefix>]\n", argv0_path);
            exit(1);
        }

        if (!extract_appimage(runimage_path, "RunDir/", pattern, true, true)) {
            exit(1);
        }

        exit(0);
    }

    // calculate full path of AppImage
    char fullpath[PATH_MAX];

    if(getenv("TARGET_APPIMAGE") == NULL) {
        // If we are operating on this file itself
        ssize_t len = readlink(runimage_path, fullpath, sizeof(fullpath));
        if (len < 0) {
            perror("Failed to obtain absolute path");
            exit(EXIT_EXECERROR);
        }
        fullpath[len] = '\0';
    } else {
        char* abspath = realpath(runimage_path, NULL);
        if (abspath == NULL) {
            perror("Failed to obtain absolute path");
            exit(EXIT_EXECERROR);
        }
        strcpy(fullpath, abspath);
        free(abspath);
    }

    if (getenv("RUNTIME_EXTRACT_AND_RUN") != NULL || (arg && strcmp(arg, "runtime-extract-and-run") == 0)) {
        char* hexlified_digest = NULL;

        // calculate MD5 hash of file, and use it to make extracted directory name "content-aware"
        // see https://github.com/AppImage/AppImageKit/issues/841 for more information
        {
            FILE* f = fopen(runimage_path, "rb");
            if (f == NULL) {
                perror("Failed to open RunImage file");
                exit(EXIT_EXECERROR);
            }

            picohash_ctx_t ctx;
            char digest[PICOHASH_MD5_DIGEST_LENGTH];
            picohash_init_md5(&ctx);
            char buf[4096];
            for (size_t bytes_read; (bytes_read = fread(buf, sizeof(char), sizeof(buf), f)) && bytes_read > 0; )
              picohash_update(&ctx, buf, bytes_read);
            picohash_final(&ctx, digest);
            hexlified_digest = appimage_hexlify(digest, sizeof(digest));
        }

        char* prefix = malloc(strlen(temp_base) + 20 + strlen(hexlified_digest) + 2);
        strcpy(prefix, temp_base);
        strcat(prefix, "/runimage_");
        strcat(prefix, hexlified_digest);
        free(hexlified_digest);

        const bool verbose = (getenv("VERBOSE") != NULL);

        if (!extract_appimage(runimage_path, prefix, NULL, false, verbose)) {
            fprintf(stderr, "Failed to extract RunImage\n");
            exit(EXIT_EXECERROR);
        }

        int pid;
        if ((pid = fork()) == -1) {
            int error = errno;
            fprintf(stderr, "fork() failed: %s\n", strerror(error));
            exit(EXIT_EXECERROR);
        } else if (pid == 0) {
            const char run_fname[] = "/Run";
            char* runfile = malloc(strlen(prefix) + 1 + strlen(run_fname) + 1);
            strcpy(runfile, prefix);
            strcat(runfile, run_fname);

            // create copy of argument list without the --runtime-extract-and-run parameter
            char* new_argv[argc];
            int new_argc = 0;
            new_argv[new_argc++] = strdup(runfile);
            for (int i = 1; i < argc; ++i) {
                if (strcmp(argv[i], "--runtime-extract-and-run") != 0) {
                    new_argv[new_argc++] = strdup(argv[i]);
                }
            }
            new_argv[new_argc] = NULL;

            /* Setting some environment variables that the app "inside" might use */
            setenv("RUNDIR", prefix, 1);

            execv(runfile, new_argv);

            int error = errno;
            fprintf(stderr, "Failed to run %s: %s\n", runfile, strerror(error));

            free(runfile);
            exit(EXIT_EXECERROR);
        }

        int status = 0;
        int rv = waitpid(pid, &status, 0);
        status = rv > 0 && WIFEXITED (status) ? WEXITSTATUS (status) : EXIT_EXECERROR;

        if (getenv("NO_CLEANUP") == NULL) {
            if (!rm_recursive(prefix)) {
                fprintf(stderr, "Failed to clean up cache directory\n");
                if (status == 0)        /* avoid messing existing failure exit status */
                  status = EXIT_EXECERROR;
            }
            rmdir(temp_base);
            rmdir(reuiddir);
        }

        // template == prefix, must be freed only once
        free(prefix);

        exit(status);
    }

    if(arg && strcmp(arg,"runtime-version")==0) {
        fprintf(stderr,"Version: %s\n", RUNTIME_VERSION);
        exit(0);
    }

    portable_option(arg, runimage_path, "home");
    portable_option(arg, runimage_path, "config");

    // If there is an argument starting with runtime- (but not runtime-mount which is handled further down)
    // then stop here and print an error message
    if((arg && strncmp(arg, "runtime-", 8) == 0) && (arg && strcmp(arg,"runtime-mount")!=0)) {
        fprintf(stderr,"--%s is not yet implemented in version %s\n", arg, RUNTIME_VERSION);
        exit(1);
    }

    if (access ("/dev/fuse", F_OK) < 0)        /* exit if libfuse cannot be used */
      {
        dprintf (2, "%s: failed to utilize FUSE during startup\n", argv[0]);
        char *title = "Cannot mount RunImage, please check your FUSE setup.";
        char *body  = "You might still be able to extract the contents of this RunImage \n"
                      "if you run it with the --runtime-extract option. \n"
                      "See https://github.com/AppImage/AppImageKit/wiki/FUSE \n"
                      "for more information";
        notify(title, body, 0); // 3 seconds timeout
        exit (-1);
      }

    int dir_fd, res;

    size_t templen = strlen(temp_base);

    // allocate enough memory (size of name won't exceed 60 bytes)
    char mount_dir[templen + 60];

    build_mount_point(mount_dir, argv[0], temp_base, templen);

    size_t mount_dir_size = strlen(mount_dir);
    pid_t pid;
    char **real_argv;
    int i;

    if (mkdir_p(temp_base, 0700) == -1) {
        perror("create parrent mount dir error");
        exit (EXIT_EXECERROR);
    }

    if (mkdtemp(mount_dir) == NULL) {
        perror ("create mount dir error");
        exit (EXIT_EXECERROR);
    }

    if (pipe (keepalive_pipe) == -1) {
        perror ("pipe error");
        exit (EXIT_EXECERROR);
    }

    pid = fork ();
    if (pid == -1) {
        perror ("fork error");
        exit (EXIT_EXECERROR);
    }

    if (pid == 0) {
        /* in child */

        char *child_argv[5];

        /* close read pipe */
        close (keepalive_pipe[0]);

        char *dir = realpath(runimage_path, NULL );

        char options[100];
        sprintf(options, "ro,offset=%lu", fs_offset);

        child_argv[0] = dir;
        child_argv[1] = "-o";
        child_argv[2] = options;
        child_argv[3] = dir;
        child_argv[4] = mount_dir;

        if(0 != fusefs_main (5, child_argv, fuse_mounted)){
            char *title;
            char *body;
            title = "Cannot mount RunImage, please check your FUSE setup.";
            body = "You might still be able to extract the contents of this RunImage \n"
            "if you run it with the --runtime-extract option. \n"
            "See https://github.com/AppImage/AppImageKit/wiki/FUSE \n"
            "for more information";
            notify(title, body, 0); // 3 seconds timeout
        };
        rmdir(temp_base);
        rmdir(reuiddir);
    } else {
        /* in parent, child is $pid */
        int c;

        /* close write pipe */
        close (keepalive_pipe[1]);

        /* Pause until mounted */
        ssize_t n = read (keepalive_pipe[0], &c, 1);
        (void) n;

        /* Fuse process has now daemonized, reap our child */
        waitpid(pid, NULL, 0);

        dir_fd = open (mount_dir, O_RDONLY);
        if (dir_fd == -1) {
            perror ("open dir error");
            exit (EXIT_EXECERROR);
        }

        res = dup2 (dir_fd, 1023);
        if (res == -1) {
            perror ("dup2 error");
            exit (EXIT_EXECERROR);
        }
        close (dir_fd);

        real_argv = malloc (sizeof (char *) * (argc + 1));
        for (i = 0; i < argc; i++) {
            real_argv[i] = argv[i];
        }
        real_argv[i] = NULL;

        if(arg && strcmp(arg, "runtime-mount") == 0) {
            char real_mount_dir[PATH_MAX];

            if (realpath(mount_dir, real_mount_dir) == real_mount_dir) {
                printf("%s\n", real_mount_dir);
            } else {
                printf("%s\n", mount_dir);
            }

            // stdout is, by default, buffered (unlike stderr), therefore in order to allow other processes to read
            // the path from stdout, we need to flush the buffers now
            // this is a less-invasive alternative to setbuf(stdout, NULL);
            fflush(stdout);

            for (;;) pause();

            exit(0);
        }

        /* Setting some environment variables that the app "inside" might use */
        setenv( "RUNIMAGE", fullpath, 1 );
        setenv( "ARGV0", argv0_path, 1 );
        setenv( "RUNDIR", mount_dir, 1 );
        setenv( "RUNOFFSET", sfs_offset, 1 );

        char portable_home_dir[PATH_MAX];
        char portable_config_dir[PATH_MAX];

        /* If there is a directory with the same name as the AppImage plus ".home", then export $HOME */
        strcpy (portable_home_dir, fullpath);
        strcat (portable_home_dir, ".home");

        /* If there is a directory with the same name as the AppImage plus ".config", then export $XDG_CONFIG_HOME */
        strcpy (portable_config_dir, fullpath);
        strcat (portable_config_dir, ".config");

        /* Original working directory */
        char cwd[1024];
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            setenv( "OWD", cwd, 1 );
        }

        char runfile[mount_dir_size + 5]; /* enough for mount_dir + "/Run" */
        strcpy(runfile, mount_dir);
        strcat(runfile, "/Run");

        /* TODO: Find a way to get the exit status and/or output of this */
        // execv(static_bash, real_argv);
        execv(runfile, real_argv);
        /* Error if we continue here */
        perror("execv error");
        exit(EXIT_EXECERROR);
    }

    return 0;
}
