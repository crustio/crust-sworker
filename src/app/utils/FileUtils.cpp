#include "FileUtils.h"

crust::Log *p_log = crust::Log::get_instance();

std::mutex g_mkdir_mutex;

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
 * @param unit -> Used to indicate KB, MB and GB
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
 * @param path -> Checked path
 * @return: Free space calculated as KB
 */
size_t get_total_space_under_dir_k(std::string path)
{
    return get_total_space_under_dir_r(path, 10);
}

/**
 * @description: Get disk free space according to path
 * @param path -> Checked path
 * @return: Free space calculated as MB
 */
size_t get_total_space_under_dir_m(std::string path)
{
    return get_total_space_under_dir_r(path, 20);
}

/**
 * @description: Get disk free space according to path
 * @param path -> Checked path
 * @return: Free space calculated as GB
 */
size_t get_total_space_under_dir_g(std::string path)
{
    return get_total_space_under_dir_r(path, 30);
}

/**
 * @description: Get free space under directory
 * @param path -> the directory path
 * @param unit -> Used to indicate KB, MB and GB
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
 * @param path -> Checked path
 * @return: Free space calculated as KB
 */
size_t get_avail_space_under_dir_k(std::string path)
{
    return get_avail_space_under_dir_r(path, 10);
}

/**
 * @description: Get disk free space according to path
 * @param path -> Checked path
 * @return: Free space calculated as MB
 */
size_t get_avail_space_under_dir_m(std::string path)
{
    return get_avail_space_under_dir_r(path, 20);
}

/**
 * @description: Get disk free space according to path
 * @param path -> Checked path
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
 * @return: Create status
 */
crust_status_t create_directory(const std::string &path)
{
    std::stack<std::string> sub_paths;
    sub_paths.push(path);
    while (!sub_paths.empty())
    {
        if (access(sub_paths.top().c_str(), 0) != -1)
        {
            sub_paths.pop();
            if (!sub_paths.empty())
            {
                if (mkdir_sync(sub_paths.top().c_str(), 0775) == -1)
                {
                    return CRUST_MKDIR_FAILED;
                }
            }
        }
        else
        {
            std::string stop = sub_paths.top();
            std::string sub_path = stop.substr(0, stop.find_last_of("/"));
            if (sub_path.size() > 1)
            {
                sub_paths.push(sub_path);
            }
        }
    }

    return CRUST_SUCCESS;
}

/**
 * @description: Rename old_path to new_path
 * @param old_path -> Old path
 * @param new_path -> New path
 * @return: Rename result
 */
crust_status_t rename_dir(std::string old_path, std::string new_path)
{
    if (access(old_path.c_str(), 0) == -1)
    {
        return CRUST_RENAME_FILE_FAILED;
    }

    if (rename(old_path.c_str(), new_path.c_str()) == -1)
    {
        p_log->err("Rename file:%s to file:%s failed!\n", old_path.c_str(), new_path.c_str());
        return CRUST_RENAME_FILE_FAILED;
    }
        
    return CRUST_SUCCESS;
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

/**
 * @description: Get file content
 * @param path -> Pointer to file path
 * @param p_data -> Pointer to pointer to file data
 * @param data_size -> Pointer to file data size
 * @return: Getting result status
 */
crust_status_t get_file(const char *path, uint8_t **p_data, size_t *data_size)
{
    crust_status_t crust_status = CRUST_SUCCESS;

    if (access(path, R_OK) == -1)
    {
        return CRUST_ACCESS_FILE_FAILED;
    }

    // Judge if given path is file
    struct stat s;
    if (stat(path, &s) == 0)
    {
        if (s.st_mode & S_IFDIR)
            return CRUST_OPEN_FILE_FAILED;
    } 

    std::ifstream in;

    in.open(path, std::ios::in | std::ios::binary);
    if (! in)
    {
        return CRUST_OPEN_FILE_FAILED;
    }

    in.seekg(0, std::ios::end);
    *data_size = in.tellg();
    in.seekg(0, std::ios::beg);

    uint8_t *p_buf = (uint8_t *)malloc(*data_size);
    if (CRUST_SUCCESS != crust_status)
    {
        in.close();
        return crust_status;
    }
    memset(p_buf, 0, *data_size);

    in.read(reinterpret_cast<char *>(p_buf), *data_size);
    in.close();

    *p_data = p_buf;

    return crust_status;
}

/**
 * @description: Store file to given path
 * @param path -> Pointer to stored path
 * @param data -> Pointer to stored data
 * @param data_size -> Stored data size
 * @return: Store result
 */
crust_status_t save_file(const char *path, const uint8_t *data, size_t data_size)
{
    return save_file_ex(path, data, data_size, 0664, SF_NONE);
}

/**
 * @description: Store file to given path and create related directory
 * @param path -> Pointer to stored path
 * @param data -> Pointer to stored data
 * @param data_size -> Stored data size
 * @param mode -> File mode
 * @param type -> Safe file type
 * @return: Store result
 */
crust_status_t save_file_ex(const char *path, const uint8_t *data, size_t data_size, mode_t mode, save_file_type_t type)
{
    if (SF_CREATE_DIR == type)
    {
        crust_status_t crust_status = CRUST_SUCCESS;
        std::string path_str(path);
        size_t last_slash = path_str.find_last_of("/");
        if (last_slash != 0 && last_slash != std::string::npos)
        {
            std::string dir_path = path_str.substr(0, last_slash);
            if (CRUST_SUCCESS != (crust_status = create_directory(dir_path)))
            {
                return crust_status;
            }
        }
    }

    std::ofstream out;
    out.open(path, std::ios::out | std::ios::binary);
    if (! out)
    {
        return CRUST_OPEN_FILE_FAILED;
    }
    Defer def_out([&out, &path, &mode](void) {
        out.close();
        chmod(path, mode);
    });

    crust_status_t crust_status = CRUST_SUCCESS;

    try
    {
        out.write(reinterpret_cast<const char *>(data), data_size);
    }
    catch (std::exception e)
    {
        crust_status = CRUST_WRITE_FILE_FAILED;
        p_log->err("Save file:%s failed! Error: %s\n", path, e.what());
    }

    out.close();

    return crust_status;
}

/**
 * @description: Get real path by type
 * @param path (in) -> Pointer to path
 * @param type -> Store type
 * @return: Real path
 */
std::string get_real_path_by_type(const char *path, store_type_t type)
{
    switch (type)
    {
        case STORE_TYPE_SRD:
            break;
        case STORE_TYPE_FILE:
            break;
        default:
            return std::string(path);
    }
    EnclaveData *ed = EnclaveData::get_instance();
    std::string r_path;
    std::string uuid(path, UUID_LENGTH * 2);
    std::string d_path = ed->get_disk_path(uuid);
    if (d_path.compare("") == 0)
    {
        p_log->warn("Cannot find path for uuid:%s\n", uuid.c_str());
        return "";
    }
    switch (type)
    {
        case STORE_TYPE_SRD:
            {
                r_path = d_path
                       + DISK_SRD_DIR
                       + "/" + std::string(path + UUID_LENGTH * 2, 2)
                       + "/" + std::string(path + UUID_LENGTH * 2 + 2, 2)
                       + "/" + std::string(path + UUID_LENGTH * 2 + 4);
                break;
            }
        case STORE_TYPE_FILE:
            {
                r_path = d_path
                       + DISK_FILE_DIR
                       + "/" + std::string(path + UUID_LENGTH * 2 + 2, 2)
                       + "/" + std::string(path + UUID_LENGTH * 2 + 4, 2)
                       + "/" + std::string(path + UUID_LENGTH * 2);
                break;
            }
        default:
            r_path = std::string(path);
    }

    return r_path;
}

/**
 * @description: Get file path by given path
 * @param path -> Pointer to file path
 * @return: File size
 */
long get_file_size(const char *path)
{
    std::string r_path = get_real_path_by_type(path, STORE_TYPE_FILE);
    struct stat stat_buf;
    int ret = stat(r_path.c_str(), &stat_buf);
    return ret == 0 ? stat_buf.st_size : 0;
}

/**
 * @description: Create directory sync
 * @param path -> Directory path
 * @param mode -> Directory mode
 * @return: Create result
 */
int mkdir_sync(const char *path, mode_t mode)
{
    SafeLock sl(g_mkdir_mutex);
    sl.lock();
    return mkdir(path, mode);
}

/**
 * @description: Get file or folder size
 * @param path -> File or folder path
 * @return: File or folder size
 */
size_t get_file_or_folder_size(std::string path)
{
    namespace fs = std::experimental::filesystem;
    size_t file_size = 0;
    fs::path folder_path(path);
    if (fs::exists(folder_path))
    {
        for (auto p : fs::directory_iterator(path))
        {
            std::string file_path = p.path();
            try
            {
                if (!fs::is_directory(p.status()))
                {
                    file_size += fs::file_size(file_path);
                }
                else
                {
                    file_size += get_file_or_folder_size(file_path);
                }
            }
            catch(std::exception& e)
            {
                p_log->warn("Get file:%s size failed! Error message:%s\n", file_path.c_str(), e.what());
            }
        }
    }

    return file_size;
}

/**
 * @description: Get file size by cid
 * @param cid -> File content id
 * @return: File size
 */
size_t get_file_size_by_cid(std::string cid)
{
    size_t file_size = 0;
    std::string path_post = std::string(DISK_FILE_DIR) + "/" + cid.substr(2,2) + "/" + cid.substr(4,2) + "/" + cid;
    json::JSON disk_json = get_disk_info();
    std::set<size_t> searched_paths;
    for (size_t i = 2; i < cid.size(); i+=2)
    {
        size_t di = (cid[i] + cid[i+1]) % disk_json.size();
        if (searched_paths.find(di) == searched_paths.end())
        {
            std::string file_path = disk_json[di][WL_DISK_PATH].ToString() + path_post;
            file_size += get_file_or_folder_size(file_path);
            searched_paths.insert(di);
        }
    }

    return file_size;
}
