#include "FileUtils.h"

/**
 * @description: get all files' name in directory
 * @param path -> the directory path
 * @return: file's name vector
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
 * @description: get all folders' name in directory
 * @param path -> the directory path
 * @return: folder's name vector
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
 * @description: recursively delete all the file in the directory
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
 * @description: recursively delete all the file in the directory or delete file
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
 * @description: get free space under directory
 * @param path -> the directory path
 * @return: free space size (M)
 */
size_t get_free_space_under_directory(std::string path)
{
    struct statfs disk_info;
    statfs(path.c_str(), &disk_info);
    unsigned long long total_blocks = disk_info.f_bsize;
    unsigned long long free_disk = disk_info.f_bfree * total_blocks;
    return free_disk >> 20;
}
