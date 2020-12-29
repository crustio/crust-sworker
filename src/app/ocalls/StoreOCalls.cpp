#include "StoreOCalls.h"

crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: Get real path by type
 * @param path -> Pointer to path
 * @param type -> Store type
 * @return: Real path
 */
std::string get_real_path_by_type(const char *path, store_type_t type)
{
    std::string r_path;
    switch (type)
    {
        case STORE_TYPE_SRD:
            r_path = Config::get_instance()->srd_path + "/" + path;
            break;
        case STORE_TYPE_FILE:
            r_path = Config::get_instance()->file_path + "/" + path;
            break;
        default:
            r_path = std::string(path);
    }

    return r_path;
}

/**
 * @description: ocall for creating directory
 * @param path -> the path of directory
 */
crust_status_t ocall_create_dir(const char *path, store_type_t type)
{
    std::string r_path = get_real_path_by_type(path, type);

    std::vector<std::string> entries;
    boost::split(entries, r_path, boost::is_any_of("/"));
    std::string cur_path = "";
    if (r_path[0] == '/')
    {
        cur_path = "/";
    }

    for (auto entry : entries)
    {
        if (entry.compare("") == 0)
            continue;

        cur_path.append(entry).append("/");
        if (access(cur_path.c_str(), 0) == -1)
        {
            if (mkdir(cur_path.c_str(), S_IRWXU) == -1)
            {
                p_log->err("Create directory:%s failed!No space or no privilege.\n", cur_path.c_str());
                return CRUST_MKDIR_FAILED;
            }
        }
    }

    return CRUST_SUCCESS;
}

/**
 * @description: ocall for renaming directory
 * @param old_path -> the old path of directory
 * @param new_path -> the new path of directory
 */
crust_status_t ocall_rename_dir(const char *old_path, const char *new_path, store_type_t type)
{
    std::string r_old_path = get_real_path_by_type(old_path, type);
    std::string r_new_path = get_real_path_by_type(new_path, type);

    if (access(r_old_path.c_str(), 0) == -1)
        return CRUST_RENAME_FILE_FAILED;

    std::vector<std::string> old_path_entry;
    std::vector<std::string> new_path_entry;
    boost::split(old_path_entry, r_old_path, boost::is_any_of("/"));
    boost::split(new_path_entry, r_new_path, boost::is_any_of("/"));

    if (old_path_entry.size() != new_path_entry.size())
    {
        p_log->err("entry size no equal!\n");
        return CRUST_RENAME_FILE_FAILED;
    }

    size_t entry_size = old_path_entry.size();
    for (size_t i = 0; i < entry_size; i++)
    {
        if (i == entry_size - 1)
        {
            if (rename(r_old_path.c_str(), r_new_path.c_str()) == -1)
            {
                p_log->err("Rename file:%s to file:%s failed!\n", r_old_path.c_str(), r_new_path.c_str());
                return CRUST_RENAME_FILE_FAILED;
            }
        }
        else if (old_path_entry[i].compare(new_path_entry[i]) != 0)
        {
            p_log->err("entry not equal!\n");
            return CRUST_RENAME_FILE_FAILED;
        }
    }

    return CRUST_SUCCESS;
}

/**
 * @description: ocall for saving data into file
 * @param path -> file path for saving
 * @param data -> data for saving
 * @param len -> the length of data
 */
crust_status_t ocall_save_file(const char *path, const unsigned char *data, size_t len, store_type_t type)
{
    std::string r_path = get_real_path_by_type(path, type);

    std::ofstream out;
    out.open(r_path.c_str(), std::ios::out | std::ios::binary);
    if (! out)
    {
        return CRUST_OPEN_FILE_FAILED;
    }

    crust_status_t crust_status = CRUST_SUCCESS;

    try
    {
        out.write(reinterpret_cast<const char *>(data), len);
    }
    catch (std::exception e)
    {
        crust_status = CRUST_WRITE_FILE_FAILED;
        p_log->err("Save file:%s failed! Error: %s\n", r_path.c_str(), e.what());
    }

    out.close();

    return crust_status;
}


crust_status_t ocall_delete_folder_or_file(const char *path, store_type_t type)
{
    std::string r_path = get_real_path_by_type(path, type);

    if (access(r_path.c_str(), 0) != -1 && rm(r_path.c_str()) == -1)
    {
        p_log->err("Delete '%s' error!\n", r_path.c_str());
        return CRUST_DELETE_FILE_FAILED;
    }

    return CRUST_SUCCESS;
}

/**
 * @description: ocall for getting file (ps: can't used by multithreading)
 * @param path -> the path of file
 * @param len -> the length of data
 * @return file data
 */
crust_status_t ocall_get_file(const char *path, unsigned char **p_file, size_t *len, store_type_t type)
{
    std::string r_path = get_real_path_by_type(path, type);

    crust_status_t crust_status = CRUST_SUCCESS;

    if (access(r_path.c_str(), 0) == -1)
    {
        return CRUST_ACCESS_FILE_FAILED;
    }

    // Judge if given path is file
    struct stat s;
    if (stat (r_path.c_str(), &s) == 0)
    {
        if (s.st_mode & S_IFDIR)
            return CRUST_OPEN_FILE_FAILED;
    } 

    std::ifstream in;

    in.open(r_path.c_str(), std::ios::out | std::ios::binary);
    if (! in)
    {
        return CRUST_OPEN_FILE_FAILED;
    }

    in.seekg(0, std::ios::end);
    *len = in.tellg();
    in.seekg(0, std::ios::beg);

    uint8_t *p_data = (uint8_t *)malloc(*len);
    memset(p_data, 0, *len);

    in.read(reinterpret_cast<char *>(p_data), *len);
    in.close();

    *p_file = p_data;

    return crust_status;
}