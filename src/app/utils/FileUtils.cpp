#include "FileUtils.h"
#include <dirent.h>

/**
 * @description: Get all files' name in directory
 * @param path -> the directory path
 * @return: File's name vector
 */
std::vector<std::string> get_files_under_path(std::string path)
{
    std::vector<std::string> files;
    DIR *dir;
    struct dirent *ptr;

    if ((dir = opendir(path.c_str())) == NULL)
    {
        perror("Open dir error...");
        exit(-1);
    }

    while ((ptr = readdir(dir)) != NULL)
    {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) // current dir OR parrent dir
        {
            continue;
        }
        else if (ptr->d_type == 8) // file
        {
            files.push_back(ptr->d_name);
        }
    }
    closedir(dir);

    return files;
}

/**
 * @description: Get all folders' name in directory
 * @param path -> the directory path
 * @return: Folder's name vector
 */
std::vector<std::string> get_folders_under_path(std::string path)
{
    std::vector<std::string> folders;
    DIR *dir;
    struct dirent *ptr;

    if ((dir = opendir(path.c_str())) == NULL)
    {
        perror("Open dir error...");
        exit(1);
    }

    while ((ptr = readdir(dir)) != NULL)
    {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0) // current dir OR parrent dir
        {
            continue;
        }
        else if (ptr->d_type == 4) // folder
        {
            folders.push_back(ptr->d_name);
        }
    }

    closedir(dir);

    return folders;
}

/**
 * @description: Recursively delete all the file in the directory
 * @param dir_full_path -> the directory path
 * @return: 0 for successed, -1 for falied
 */
int rm_dir(std::string dir_full_path)
{
    DIR *dirp = opendir(dir_full_path.c_str());
    if (!dirp)
    {
        return -1;
    }
    struct dirent *dir;
    struct stat st;
    while ((dir = readdir(dirp)) != NULL)
    {
        if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0)
        {
            continue;
        }
        std::string sub_path = dir_full_path + '/' + dir->d_name;
        if (lstat(sub_path.c_str(), &st) == -1)
        {
            continue;
        }
        if (S_ISDIR(st.st_mode))
        {
            if (rm_dir(sub_path) == -1)
            {
                closedir(dirp);
                return -1;
            }
            rmdir(sub_path.c_str());
        }
        else if (S_ISREG(st.st_mode))
        {
            unlink(sub_path.c_str());
        }
        else
        {
            continue;
        }
    }
    if (rmdir(dir_full_path.c_str()) == -1) //delete dir itself.
    {
        closedir(dirp);
        return -1;
    }
    closedir(dirp);
    return 0;
}

/**
 * @description: Recursively delete all the file in the directory or delete file
 * @param path -> the directory path or filepath
 * @return: 0 for successed, -1 for falied
 */
int rm(std::string path)
{
    std::string file_path = path;
    struct stat st;
    if (lstat(file_path.c_str(), &st) == -1)
    {
        return -1;
    }
    if (S_ISREG(st.st_mode))
    {
        if (unlink(file_path.c_str()) == -1)
        {
            return -1;
        }
    }
    else if (S_ISDIR(st.st_mode))
    {
        if (path == "." || path == "..")
        {
            return -1;
        }
        if (rm_dir(file_path) == -1) //delete all the files in dir.
        {
            return -1;
        }
    }
    return 0;
}

/**
 * @description: Get free space under directory
 * @param path -> the directory path
 * @return: Free space size (M)
 */
size_t get_total_space_under_dir_r(std::string path, uint32_t unit)
{
    struct statfs disk_info;
    if (statfs(path.c_str(), &disk_info) == -1)
    {
        return 0;
    }
    size_t avail_disk = (size_t)disk_info.f_blocks * (size_t)disk_info.f_bsize;
    return avail_disk >> unit;
}

/**
 * @description: Get disk free space according to path
 * @return: Free space calculated as KB
 */
size_t get_total_space_under_dir_k(std::string path)
{
    return get_total_space_under_dir_r(path, 10);
}

/**
 * @description: Get disk free space according to path
 * @return: Free space calculated as MB
 */
size_t get_total_space_under_dir_m(std::string path)
{
    return get_total_space_under_dir_r(path, 20);
}

/**
 * @description: Get disk free space according to path
 * @return: Free space calculated as GB
 */
size_t get_total_space_under_dir_g(std::string path)
{
    return get_total_space_under_dir_r(path, 30);
}

/**
 * @description: Get free space under directory
 * @param path -> the directory path
 * @return: Free space size (M)
 */
size_t get_avail_space_under_dir_r(std::string path, uint32_t unit)
{
    struct statfs disk_info;
    if (statfs(path.c_str(), &disk_info) == -1)
    {
        return 0;
    }
    size_t avail_disk = (size_t)disk_info.f_bavail * (size_t)disk_info.f_bsize;
    return avail_disk >> unit;
}

/**
 * @description: Get disk free space according to path
 * @return: Free space calculated as KB
 */
size_t get_avail_space_under_dir_k(std::string path)
{
    return get_avail_space_under_dir_r(path, 10);
}

/**
 * @description: Get disk free space according to path
 * @return: Free space calculated as MB
 */
size_t get_avail_space_under_dir_m(std::string path)
{
    return get_avail_space_under_dir_r(path, 20);
}

/**
 * @description: Get disk free space according to path
 * @return: Free space calculated as GB
 */
size_t get_avail_space_under_dir_g(std::string path)
{
    return get_avail_space_under_dir_r(path, 30);
}

/**
 * @description: Get free space under directory
 * @param path -> the directory path
 * @return: Free space size (M)
 */
size_t get_free_space_under_directory(std::string path)
{
    struct statfs disk_info;
    if (statfs(path.c_str(), &disk_info) == -1)
    {
        return 0;
    }
    size_t total_blocks = disk_info.f_bsize;
    size_t free_disk = (size_t)disk_info.f_bfree * total_blocks;
    return free_disk >> 20;
}

/**
 * @description: Create directory
 * @param path -> the directory path
 */
bool create_directory(std::string path)
{
    if (access(path.c_str(), 0) == -1)
    {
        // TODO: If we run this in windows?
        if (system((std::string("mkdir -p ") + path).c_str()) == -1)
        {
            return false;
        }
    }
    return true;
}

/**
 * @description: Get sub folders and files in indicated path
 * @param path -> Indicated path
 * @return: Array of sub folders and files
 */
std::vector<std::string> get_sub_folders_and_files(const char *path)
{
    DIR *dir;
    struct dirent *ent;
    std::vector<std::string> dirs;
    if ((dir = opendir(path)) != NULL)
    {
        while ((ent = readdir(dir)) != NULL)
        {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
                continue;

            dirs.push_back(std::string(ent->d_name));
        }
        closedir(dir);
    }

    return dirs;
}
