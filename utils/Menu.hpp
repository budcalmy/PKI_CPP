#pragma once

#include <iostream>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

class Menu {
private:
public:
    void displayDirectoryContents(const std::string& dir) const;
};

void Menu::displayDirectoryContents(const std::string& dir) const {

    if (!fs::exists(dir)) {
        std::cerr << "Путь не существует: " << dir << std::endl;
        return;
    }

    if (!fs::is_directory(dir)) {
        std::cerr << "Указанный путь не является директорией: " << dir << std::endl;
        return;
    }

    int index = 1;
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (fs::is_regular_file(entry.status())) {
            std::cout << index << ". " << entry.path().filename().string()
                        << " | " << entry.path() << std::endl;
            index++;
        }
    }
}