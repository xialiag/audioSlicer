#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <regex>
#include <sstream>
#include <filesystem>
#include <Windows.h>
#include <chrono>
#include <future>
#include <condition_variable>
#include <atomic>
#include <array>
#include <io.h>
#include <random>
#include <map>
#include <format>

namespace fs = std::filesystem;
using namespace std::chrono;

// 控制台编码设置初始化
class ConsoleEncoding {
public:
    ConsoleEncoding() {
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
        std::locale::global(std::locale(""));
        std::wcout.imbue(std::locale(""));
        std::wcerr.imbue(std::locale(""));
    }
};
static ConsoleEncoding init_console_encoding;

// 配置参数
double SILENCE_THRESHOLD = -50.0;   // 静音阈值(dB)
double SILENCE_DURATION = 0.1;      // 静音最短持续时间(秒)
double MAX_CLIP_DURATION = 60.0;    // 最大剪辑长度(秒)
double MIN_CLIP_DURATION = 0.1;     // 最小剪辑长度(秒)

// 全局原子变量
std::atomic<size_t> processed_files{ 0 };
std::atomic<size_t> running_tasks{ 0 };
size_t total_files = 0;

// 进程池控制类
class ProcessPool {
    std::mutex pool_mutex;
    std::condition_variable pool_cv;
    std::atomic<int> available_slots;
public:
    ProcessPool(int max_concurrent) : available_slots(max_concurrent) {}

    void acquire() {
        std::unique_lock<std::mutex> lock(pool_mutex);
        pool_cv.wait(lock, [this] { return available_slots > 0; });
        --available_slots;
    }

    void release() {
        {
            std::lock_guard<std::mutex> lock(pool_mutex);
            ++available_slots;
        }
        pool_cv.notify_one();
    }
};

// 全局变量
std::mutex queue_mutex;
std::condition_variable queue_cv;
std::queue<fs::path> file_queue;
std::atomic<bool> stop_flag{ false };
ProcessPool* ffmpeg_pool;

// 状态同步变量
std::mutex status_mutex;
std::condition_variable status_cv;

struct AudioSegment {
    double start;
    double end;
};

class EncodingConverter {
public:
    static std::string WideToUTF8(const std::wstring& wstr) {
        if (wstr.empty()) return "";
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(),
            NULL, 0, NULL, NULL);
        std::string str(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(),
            &str[0], size_needed, NULL, NULL);
        return str;
    }

    static std::wstring UTF8ToWide(const std::string& str) {
        if (str.empty()) return L"";
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(),
            NULL, 0);
        std::wstring wstr(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(),
            &wstr[0], size_needed);
        return wstr;
    }
};

std::string generate_random_string(size_t length) {
    static const std::string chars =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<size_t> dist(0, chars.size() - 1);

    std::string s;
    s.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        s += chars[dist(rng)];
    }
    return s;
}

std::string escape_path(const fs::path& p) {
    const DWORD buf_size = GetShortPathNameW(p.c_str(), NULL, 0);
    if (buf_size == 0) return "\"" + p.string() + "\"";

    std::wstring short_path(buf_size, L'\0');
    GetShortPathNameW(p.c_str(), &short_path[0], buf_size);
    short_path.resize(wcslen(short_path.c_str()));

    std::string s = EncodingConverter::WideToUTF8(short_path);

    size_t pos = 0;
    while ((pos = s.find_first_of(R"( &!^)", pos)) != std::string::npos) {
        s.insert(pos, "^");
        pos += 2;
    }
    return "\"" + s + "\"";
}

double parse_time(const std::string& t) {
    try {
        return std::stod(t);
    }
    catch (...) {
        std::cerr << std::format("[ERROR] 时间解析失败: {}\n", t);
        return 0.0;
    }
}

std::string execute_command(const std::string& cmd) {
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        throw std::runtime_error("创建管道失败");
    }

    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(STARTUPINFOW);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.wShowWindow = SW_HIDE;

    std::wstring wcmd = L"cmd.exe /C " + EncodingConverter::UTF8ToWide(cmd);
    wchar_t* cmdline = _wcsdup(wcmd.c_str());

    if (!CreateProcessW(NULL, cmdline, NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        free(cmdline);
        CloseHandle(hWrite);
        CloseHandle(hRead);
        throw std::runtime_error("创建进程失败");
    }
    free(cmdline);
    CloseHandle(hWrite);

    std::string result;
    char buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hRead, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        result.append(buffer, bytesRead);
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);

    if (exitCode != 0) {
        throw std::runtime_error(std::format("命令执行失败，退出码: {}", exitCode));
    }

    return result;
}

std::vector<AudioSegment> parse_silence_intervals(const std::string& output, double& total_duration) {
    std::vector<AudioSegment> silence;
    std::regex duration_re(R"(Duration:\s*(\d+):(\d+):(\d+\.\d+))");
    std::regex silence_start_re(R"(silence_start:\s*(\d+\.?\d*))");
    std::regex silence_end_re(R"(silence_end:\s*(\d+\.?\d*))");

    std::istringstream iss(output);
    std::string line;
    double current_start = -1.0;

    while (std::getline(iss, line)) {
        std::smatch match;
        if (std::regex_search(line, match, duration_re) && match.size() == 4) {
            int hours = std::stoi(match[1]);
            int minutes = std::stoi(match[2]);
            double seconds = parse_time(match[3]);
            total_duration = hours * 3600 + minutes * 60 + seconds;
            break;
        }
    }

    iss.clear();
    iss.seekg(0);
    while (std::getline(iss, line)) {
        std::smatch match;
        if (std::regex_search(line, match, silence_start_re) && match.size() == 2) {
            current_start = parse_time(match[1]);
        }
        else if (std::regex_search(line, match, silence_end_re) && match.size() == 2) {
            if (current_start != -1.0) {
                double end_time = parse_time(match[1]);
                silence.push_back({ current_start, end_time });
                current_start = -1.0;
            }
        }
    }

    return silence;
}

std::vector<AudioSegment> find_valid_segments(const std::vector<AudioSegment>& silence, double total_duration) {
    std::vector<AudioSegment> valid;

    auto check_and_add = [&](double start, double end) {
        const double duration = end - start;

        if (duration > MAX_CLIP_DURATION) {
            std::cout << std::format("[FILTER] 跳过超长片段: {:.1f}s-{:.1f}s ({:.1f}秒)\n",
                start, end, duration);
            return;
        }
        if (duration >= MIN_CLIP_DURATION) {
            valid.push_back({ start, end });
            std::cout << std::format("[ACCEPT] 有效片段: {:.1f}s-{:.1f}s ({:.1f}秒)\n",
                start, end, duration);
        }
        else {
            std::cout << std::format("[FILTER] 跳过短片段: {:.1f}s-{:.1f}s ({:.1f}秒)\n",
                start, end, duration);
        }
        };

    if (silence.empty()) {
        check_and_add(0.0, total_duration);
        return valid;
    }

    if (silence[0].start > MIN_CLIP_DURATION) {
        check_and_add(0.0, silence[0].start);
    }

    for (size_t i = 1; i < silence.size(); ++i) {
        const double start = silence[i - 1].end;
        const double end = silence[i].start;
        check_and_add(start, end);
    }

    const double last_end = silence.back().end;
    if (total_duration - last_end > MIN_CLIP_DURATION) {
        check_and_add(last_end, total_duration);
    }

    return valid;
}

void process_file(const fs::path& original_path) {
    running_tasks.fetch_add(1);
    fs::path temp_path;
    try {
        // 生成12位随机字符串的临时文件名
        std::string temp_name;
        do {
            temp_name = std::format("tmp_{}.m4a", generate_random_string(12));
            temp_path = original_path.parent_path() / temp_name;
        } while (fs::exists(temp_path));

        // 重命名原始文件到临时文件
        fs::rename(original_path, temp_path);
        std::cout << std::format("[PROCESS] 开始处理: {}\n",
            original_path.filename().string());
        std::cout << std::format("[RENAME] 临时文件: {}\n",
            temp_path.filename().string());

        fs::path temp_output_dir = temp_path.parent_path() / temp_path.stem();
        fs::create_directories(temp_output_dir);

        // 检测静音区间
        std::cout << "[DETECT] 正在分析静音区间...\n";
        std::string detect_cmd = std::format(
            "ffmpeg -hide_banner -i {} -af silencedetect=noise={}dB:d={} -f null - 2>&1",
            escape_path(temp_path), SILENCE_THRESHOLD, SILENCE_DURATION);

        std::string detect_output = execute_command(detect_cmd);
        double total_duration = 0;
        auto silence = parse_silence_intervals(detect_output, total_duration);
        auto valid_segments = find_valid_segments(silence, total_duration);

        // 处理有效片段
        std::cout << std::format("[SPLIT] 发现{}个有效片段\n", valid_segments.size());
        std::vector<std::future<void>> futures;
        for (size_t i = 0; i < valid_segments.size(); ++i) {
            const double start = valid_segments[i].start;
            const double end = valid_segments[i].end;
            const double duration = end - start;

            fs::path output_path = temp_output_dir /
                std::format("{}_{}.m4a", temp_path.stem().string(), i + 1);

            std::string clip_cmd = std::format(
                "ffmpeg -hide_banner -y -ss {} -i {} -t {} -c copy {}",
                start, escape_path(temp_path), duration, escape_path(output_path));

            futures.push_back(std::async(std::launch::async,
                [clip_cmd, output_path]() {
                    try {
                        ffmpeg_pool->acquire();
                        std::string output = execute_command(clip_cmd);
                        if (output.find("Output file is empty") != std::string::npos) {
                            fs::remove(output_path);
                            std::cerr << std::format("[WARNING] 无效片段已跳过: {}\n",
                                output_path.filename().string());
                        }
                        ffmpeg_pool->release();
                    }
                    catch (const std::exception& e) {
                        ffmpeg_pool->release();
                        std::cerr << std::format("[ERROR] 剪辑失败: {} - {}\n",
                            output_path.filename().string(),
                            e.what());
                    }
                }));
        }

        for (auto& f : futures) f.wait();

        // 恢复原始文件名
        fs::rename(temp_path, original_path);
        std::cout << std::format("[CLEAN] 清理临时文件: {}\n",
            temp_path.filename().string());

        // 移动输出目录到原始位置
        fs::path original_output_dir = original_path.parent_path() / original_path.stem();
        if (fs::exists(temp_output_dir)) {
            if (fs::exists(original_output_dir)) {
                fs::remove_all(original_output_dir);
            }
            fs::rename(temp_output_dir, original_output_dir);

            // 重命名剪辑文件
            for (const auto& entry : fs::directory_iterator(original_output_dir)) {
                fs::path old_path = entry.path();
                std::string filename = old_path.filename().string();
                size_t pos = filename.rfind('_');
                if (pos != std::string::npos) {
                    std::string new_filename = std::format("{}{}",
                        original_path.stem().string(),
                        filename.substr(pos));
                    fs::path new_path = old_path.parent_path() / new_filename;
                    fs::rename(old_path, new_path);
                }
            }
        }

        std::cout << std::format("[SUCCESS] 处理完成: {} → {}个片段\n{}\n",
            original_path.filename().string(),
            valid_segments.size(),
            std::string(60, '─'));
    }
    catch (const std::exception& e) {
        // 异常时尝试恢复文件名
        if (!temp_path.empty() && fs::exists(temp_path)) {
            try {
                fs::rename(temp_path, original_path);
                std::cerr << std::format("[RECOVER] 已恢复原始文件: {}\n",
                    original_path.filename().string());
            }
            catch (...) {
                std::cerr << std::format("[CRITICAL] 无法恢复文件: {}\n",
                    original_path.filename().string());
            }
        }
        std::cerr << std::format("[FAILURE] 处理失败: {} - {}\n{}\n",
            original_path.filename().string(),
            e.what(),
            std::string(60, '═'));
    }
    processed_files.fetch_add(1);
    running_tasks.fetch_sub(1);
    status_cv.notify_one();
}

void worker_thread() {
    while (!stop_flag) {
        fs::path file_path;
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            queue_cv.wait_for(lock, 100ms, [] { return !file_queue.empty() || stop_flag; });

            if (file_queue.empty()) continue;
            file_path = file_queue.front();
            file_queue.pop();
        }
        process_file(file_path);
    }
}

void print_status() {
    auto remaining = total_files - processed_files;
    std::cout << std::format(
        "[STATUS] 已完成: {}/{} | 进行中: {} | 剩余: {}\n",
        processed_files.load(),
        total_files,
        running_tasks.load(),
        remaining
    );
}

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    if (argc < 3) {
        std::cout << std::format("用法: {} <输入目录> <线程数> [最大剪辑长度(秒)] [最小剪辑长度(秒)]\n", argv[0]);
        return 1;
    }

    fs::path input_dir(argv[1]);
    int num_threads = std::stoi(argv[2]);

    // 解析可选参数
    if (argc >= 4) MAX_CLIP_DURATION = std::stod(argv[3]);
    if (argc >= 5) MIN_CLIP_DURATION = std::stod(argv[4]);

    ffmpeg_pool = new ProcessPool(num_threads);

    try {
        std::cout << std::format("\n{0}\n[INIT] 扫描目录: {1}\n[CONFIG] 参数设置:\n"
            "  最大剪辑长度: {2}秒\n  最小剪辑长度: {3}秒\n  工作线程数: {4}\n{0}\n",
            std::string(60, '='),
            input_dir.string(),
            MAX_CLIP_DURATION,
            MIN_CLIP_DURATION,
            num_threads);

        size_t file_count = 0;
        for (const auto& entry : fs::directory_iterator(input_dir)) {
            if (entry.path().extension() == ".m4a") {
                fs::path original_path = entry.path();
                {
                    std::lock_guard<std::mutex> lock(queue_mutex);
                    file_queue.push(original_path);
                    ++file_count;
                }
            }
        }
        total_files = file_count;
        std::cout << std::format("[SCAN] 发现 {} 个音频文件\n{}\n",
            file_count,
            std::string(60, '-'));
    }
    catch (const std::exception& e) {
        std::cerr << std::format("[ERROR] 目录扫描失败: {}\n", e.what());
        return 1;
    }

    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(worker_thread);
    }

    // 初始状态显示
    print_status();

    // 动态状态更新
    size_t last_processed = 0;
    while (processed_files < total_files) {
        std::unique_lock<std::mutex> lock(status_mutex);
        status_cv.wait(lock, [&] {
            return processed_files > last_processed || stop_flag;
            });

        if (processed_files > last_processed) {
            print_status();
            last_processed = processed_files.load();
        }
    }

    stop_flag = true;
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    delete ffmpeg_pool;
    std::cout << std::format("\n{0}\n[COMPLETE] 全部处理完成\n{0}\n",
        std::string(60, '='));
    return 0;
}