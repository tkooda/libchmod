/*
 * libchmod.c : v0.1
 * 
 * http://devsec.org/software/libchmod/
 * 
 * Thor Kooda
 * 2006-02-01
 * 
 * NOTES:
 *   - a shared library to hijack+limit chmod() based on a path regex
 *   - will return ENOMEM on config error
 *   - will return EPERM on limit error
 * 
 * COMPILE:
 *   gcc -fPIC -rdynamic -Wall -g -c libchmod.c
 *   gcc -shared -Wl,-soname,libchmod.so.1 -o libchmod.so.1.0.1 libchmod.o -lc -ldl
 * 
 * SAMPLE REQUIRED ENVIRONMENT:
 *   LIBCHMOD_PATH_LIB_ORIG="/lib/libc.so.6"
 *   LIBCHMOD_PATH_REGEX="^/var/"
 *   LIBCHMOD_MODE_DIR_ALLOWED="2775"
 *   LIBCHMOD_MODE_DIR_REQUIRED="775"
 *   LIBCHMOD_MODE_FILE_ALLOWED="775"
 *   LIBCHMOD_MODE_FILE_REQUIRED="664"
 * 
 * USAGE:
 *   export LD_PRELOAD=./libchmod.so.1.0.1
 *   exec chmod $@
 * 
 * WHY:
 *   - some of my users still have trouble with unix perms
 *   - umask is insufficient
 *   - selinux is to much overhead
 * 
 * TODO:
 *   - fchmod() ?
 * 
*/


#include <regex.h>
#include <stdio.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>
#include <dlfcn.h>
#include <stdlib.h>

#define CHMOD_ERR (-1)

int match(const char *string, const char *pattern)
{
  int status;
  regex_t re;
  
  if ( regcomp(&re, pattern, REG_EXTENDED|REG_NOSUB) != 0 ) {
    return(0); // error
  }
  status = regexec(&re, string, (size_t) 0, NULL, 0);
  regfree(&re);
  return (status == 0);
}

int chmod(const char *path, mode_t mode)
{
  char *env_path_lib_orig, *env_path_regex;
  void *handle;
  int (*orig_chmod)(const char *path, mode_t mode);
  char resolved_path[PATH_MAX+1];
  struct stat st_p;
  char *env_mode_dir_required, *env_mode_dir_allowed, *env_mode_file_required, *env_mode_file_allowed;
  long long_mode_dir_required, long_mode_dir_allowed, long_mode_file_required, long_mode_file_allowed;
  char **endptr;
  long mode_l = mode;
  
  if ( ( env_path_lib_orig = getenv("LIBCHMOD_PATH_LIB_ORIG") ) == NULL ) {
    errno = ENOMEM;
    return(CHMOD_ERR);
  }
  
  /* open the library that contains chmod() */
  if ( ( handle = dlopen(env_path_lib_orig, RTLD_LAZY) ) == NULL ) {
    errno = ENOMEM;
    return(CHMOD_ERR);
  }
  
  /* save a pointer to origional chmod() function */
  if ( ( orig_chmod = dlsym(handle, "chmod") ) == NULL ) {
    dlclose(handle);
    errno = ENOMEM;
    return(CHMOD_ERR);
  }
  
  /* check path */
  if ( ( env_path_regex = getenv("LIBCHMOD_PATH_REGEX") ) == NULL ) {
    errno = ENOMEM;
    return(CHMOD_ERR);
  }
  
  /* resolve the actual path */
  if ( ! realpath(path, resolved_path) ) {
    return(CHMOD_ERR); // realpath() sets errno
  }
  
  /* check path against regex */
  if ( ! match(resolved_path, env_path_regex) ) {
    return orig_chmod(path, mode); // passthrough
  }
  
  /* check type */
  if ( stat(resolved_path, &st_p ) ) {
    return(CHMOD_ERR); // stat() sets errno
  }
  
  /* check perms */
  if ( S_ISDIR( st_p.st_mode ) ) { // on dirs..
    
    if ( ( env_mode_dir_allowed = getenv("LIBCHMOD_MODE_DIR_ALLOWED") ) == NULL ) {
      errno = ENOMEM;
      return(CHMOD_ERR);
    }
    
    if ( ( env_mode_dir_required = getenv("LIBCHMOD_MODE_DIR_REQUIRED") ) == NULL ) {
      errno = ENOMEM;
      return(CHMOD_ERR);
    }
    
    long_mode_dir_allowed = strtol( env_mode_dir_allowed, endptr, 8 );
    long_mode_dir_required = strtol( env_mode_dir_required, endptr, 8 );
    
    if ( ( mode_l | long_mode_dir_allowed ) != long_mode_dir_allowed ) {
      errno = EPERM;
      return(CHMOD_ERR);
    }
    
    if ( ( mode_l | long_mode_dir_required ) != mode_l ) {
      errno = EPERM;
      return(CHMOD_ERR);
    }
    
  } else if ( S_ISREG( st_p.st_mode ) ) { // on files..
    
    if ( ( env_mode_file_allowed = getenv("LIBCHMOD_MODE_FILE_ALLOWED") ) == NULL ) {
      errno = ENOMEM;
      return(CHMOD_ERR);
    }
    
    if ( ( env_mode_file_required = getenv("LIBCHMOD_MODE_FILE_REQUIRED") ) == NULL ) {
      errno = ENOMEM;
      return(CHMOD_ERR);
    }
    
    long_mode_file_allowed = strtol( env_mode_file_allowed, endptr, 8 );
    long_mode_file_required = strtol( env_mode_file_required, endptr, 8 );
    
    if ( ( mode_l | long_mode_file_allowed ) != long_mode_file_allowed ) {
      errno = EPERM;
      return(CHMOD_ERR);
    }
    
    if ( ( mode_l | long_mode_file_required ) != mode_l ) {
      errno = EPERM;
      return(CHMOD_ERR);
    }
    
  }
  
  /* do real chmod() */
  return orig_chmod( path, mode );
}

