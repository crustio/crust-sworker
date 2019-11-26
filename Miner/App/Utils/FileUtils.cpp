#include "FileUtils.h"

std::vector<std::string> get_files_under_path(std::string path)
{
    std::vector<std::string> files;
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
        else if (ptr->d_type == 8) // file
        {
            files.push_back(ptr->d_name);
        }
    }
    closedir(dir);

    return files;
}

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
