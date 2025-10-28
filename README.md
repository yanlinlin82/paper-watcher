# 科研文献跟踪网站

## 简介

这是一个能够自动跟踪最新科研文献的网站模板。

网站所展示的内容，来自每天自动获取PubMed最新文献数据，并使用大语言模型对文献标题和摘要进行分析，总结得到其创新点、研究目的、研究对象等字段信息，可方便跟踪特定方向的研究进展。

作为实例，目前已经部署了四个网站，供感兴趣的伙伴们在线查询和浏览（或象征性付费后下载完整Excel表格）：

- [单细胞与空转测序相关文章](https://single-cell-papers.bioinfo-assist.com/)
- [深度学习在生物医药领域的应用](https://biomed-dl.bioinfo-assist.com/)
- [合成生物学相关文章](https://synthetic-biology-papers.bioinfo-assist.com/)
- [生物计算机与DNA存储相关文章](https://biological-computing-papers.bioinfo-assist.com/)

---

## 动机

我曾在 [NCBI PubMed](https://pubmed.ncbi.nlm.nih.gov/) 订阅了诸如 `"deep learning" OR "convolutional neural networks"` 等关键词，于是每天都会收到数十至数百篇相关文献的邮件推送。这些文献内容纷繁、涉猎广泛，但都与生物医药相关，对于持续跟进和了解相关领域最新前沿进展，起到了莫大帮助。然而，随着相关领域变得火热，推送的文献数量变得越来越多，光是快速浏览每篇文章的标题和摘要，每天都会花掉不少时间。所幸，近两年大语言模型（LLM）迅速崛起，让自动化的文献整理和信息提取变得可能，因此，作为一项应用尝试，本项目得以创建和持续改进。

## 快速上手

1. 克隆本仓库：

    ```sh
    git clone https://github.com/yanlinlin82/paper-watcher.git
    ```

2. 准备环境

    ```sh
    # 安装 uv
    curl -LsSf https://astral.sh/uv/install.sh | sh

    # 安装依赖包
    uv sync
    ```

3. 配置环境参数

    ```sh
    vi .env
    ```

    ```txt
    OPENAI_BASE_URL=https://api.deepseek.com  # 若使用 openai API，则留空，或使用 https://api.openai.com/v1
    OPENAI_API_KEY=sk-XXXX                    # 填写自己账号的 API Key
    OPENAI_MODEL=deepseek-chat                # 若使用 openai API，可设置为 gpt-4o-mini
    OPENAI_PROXY_URL=socks5://x.x.x.x:xxxx    # 用于（从国内翻墙）调用 openai API，使用 DeepSeek 则可不配置此项

    TITLE=关于XXX的文章
    KEYWORDS_FILE=data/xxx/keywords.txt  # 文本文件，每行一个关键词（匹配任何一个的文献会保留下来，继续分析）
    ```

4. 初始化并运行Django

    ```sh
    uv run manage.py migrate
    uv run manage.py collectstatic
    ```

5. PubMed数据获取

    ```sh
    lftp -c "mirror -c https://ftp.ncbi.nlm.nih.gov/pubmed/" # 注意全套下载有超过50G
    ```

    PubMed数据每日更新，在相同目录中运行上述命令，即可自动增量下载

6. 扫描PubMed文件，提取文献信息，导入数据库

    ```sh
    python scripts/scan-pubmed.py /path/to/pubmed/updatefiles/pubmedXXnXXXX.xml.gz
    ```

    上述命令每次只导入一个`pubmedXXnXXXX.xml.gz`文件（通常含有上万篇文献）中的匹配关键词的文献信息。如果希望扫描并导入全部PubMed数据，则可以使用如下bash循环：

    ```sh
    find /path/to/pubmed/{baseline,updatefiles}/ -type f -name 'pubmed*.xml.gz' \
        | sort -r \
        | while read f; do
        python scripts/scan-pubmed.py "$f"
        sleep 1
    done
    ```

## 免责声明

本项目信息由手工或AI整理，信息难免存在错漏，请使用时务必注意核实。此外，由于各种原因，项目可能会不定期断档停更，还请见谅！

## 许可证

本仓库基于 [MIT协议](LICENSE) 发布，允许自由修改和传播。
