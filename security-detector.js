/**
 * 网址安全检测模块
 * 用于检测HTTP请求中的各种安全漏洞，如SQL注入、文件上传漏洞、XSS、CSRF等
 */

class SecurityDetector {
    constructor() {
        this.config = {
            enableSqlInjectionDetection: true,
            enableFileUploadDetection: true,
            enableXssDetection: true,
            enableCsrfDetection: true,
            enablePathTraversalDetection: true,
            enableCommandInjectionDetection: true,
            enableSensitiveInfoLeakDetection: true,
            enableHttpParameterPollutionDetection: true,
            enableJsonInjectionDetection: true,
            enableXmlInjectionDetection: true,
            enableSsrfDetection: true
        };
    }

    /**
     * 设置检测配置
     * @param {Object} config - 检测配置
     */
    setConfig(config) {
        this.config = { ...this.config, ...config };
    }

    /**
     * 检测单个HTTP请求的安全性
     * @param {Object} httpPacket - HTTP数据包
     * @returns {Object} - 检测结果
     */
    detect(httpPacket) {
        const results = {
            isSecure: true,
            threats: [],
            details: {}
        };

        // 获取HTTP请求信息
        const httpInfo = httpPacket.layers?.application?.httpInfo;
        if (!httpInfo) {
            return results;
        }

        // 检测URL路径
        const path = httpInfo.path || '';
        // 检测请求方法
        const method = httpInfo.method || '';
        // 检测请求头
        const headers = httpInfo.headers || {};
        // 检测请求体
        const body = httpInfo.body || '';

        // 综合检测
        const detectionResults = {
            sqlInjection: this.config.enableSqlInjectionDetection ? this.detectSqlInjection(path, method, body) : null,
            fileUpload: this.config.enableFileUploadDetection ? this.detectFileUpload(path, method, headers, body) : null,
            xss: this.config.enableXssDetection ? this.detectXss(path, body) : null,
            csrf: this.config.enableCsrfDetection ? this.detectCsrf(method, headers) : null,
            pathTraversal: this.config.enablePathTraversalDetection ? this.detectPathTraversal(path) : null,
            commandInjection: this.config.enableCommandInjectionDetection ? this.detectCommandInjection(path, body) : null,
            sensitiveInfoLeak: this.config.enableSensitiveInfoLeakDetection ? this.detectSensitiveInfoLeak(path, body) : null,
            httpParameterPollution: this.config.enableHttpParameterPollutionDetection ? this.detectHttpParameterPollution(path) : null,
            jsonInjection: this.config.enableJsonInjectionDetection ? this.detectJsonInjection(body) : null,
            xmlInjection: this.config.enableXmlInjectionDetection ? this.detectXmlInjection(body) : null,
            ssrf: this.config.enableSsrfDetection ? this.detectSsrf(path, headers) : null
        };

        // 汇总检测结果
        Object.entries(detectionResults).forEach(([type, result]) => {
            if (result && result.isThreat) {
                results.isSecure = false;
                results.threats.push(type);
                results.details[type] = result;
            }
        });

        return results;
    }

    /**
     * 检测SQL注入
     * @param {string} path - URL路径
     * @param {string} method - 请求方法
     * @param {string} body - 请求体
     * @returns {Object} - 检测结果
     */
    detectSqlInjection(path, method, body) {
        // SQL注入特征模式，包含具体类型
        const sqlPatterns = [
            {
                pattern: /('|").*(OR|AND).*(=|LIKE|IN|NOT).*('|")/i,
                type: '联合注入',
                description: '通过添加OR/AND条件尝试绕过认证或获取更多数据'
            },
            {
                pattern: /('|").*('|")/i,
                type: '单引号注入',
                description: '通过单引号/双引号尝试闭合SQL语句，可能导致语法错误或信息泄露'
            },
            {
                pattern: /(--|#|\/\*)/,
                type: '注释注入',
                description: '通过添加注释符尝试篡改SQL语句逻辑'
            },
            {
                pattern: /(SELECT.*FROM|UNION.*SELECT)/i,
                type: 'UNION查询注入',
                description: '通过UNION操作符尝试获取其他表的数据'
            },
            {
                pattern: /(DROP|ALTER|TRUNCATE|EXECUTE|EXEC)/i,
                type: '破坏型注入',
                description: '尝试执行破坏性SQL语句，如删除表、修改结构等'
            },
            {
                pattern: /(1=1|0=1|TRUE|FALSE)/i,
                type: '条件注入',
                description: '通过恒真/恒假条件尝试绕过认证'
            },
            {
                pattern: /(CAST|CONVERT|CHAR|VARCHAR|NVARCHAR|TEXT|NTEXT|INT|BIGINT|FLOAT|DOUBLE|DECIMAL|NUMERIC|DATETIME|DATE|TIME)/i,
                type: '类型转换注入',
                description: '通过类型转换函数尝试绕过过滤或获取数据'
            },
            {
                pattern: /(INFORMATION_SCHEMA|sys.objects|sys.tables|sys.columns|sys.views)/i,
                type: '元数据注入',
                description: '尝试访问数据库元数据，获取表结构等敏感信息'
            }
        ];

        // 合并所有待检测的字符串
        const combined = [path, body].join(' ');
        
        // 检测每个模式
        for (const sqlPattern of sqlPatterns) {
            if (sqlPattern.pattern.test(combined)) {
                const match = combined.match(sqlPattern.pattern)[0];
                return {
                    isThreat: true,
                    type: 'sql_injection',
                    message: `检测到SQL注入攻击特征 - ${sqlPattern.type}`,
                    injectionType: sqlPattern.type,
                    description: sqlPattern.description,
                    evidence: match
                };
            }
        }

        return { isThreat: false };
    }

    /**
     * 检测文件上传漏洞
     * @param {string} path - URL路径
     * @param {string} method - 请求方法
     * @param {Object} headers - 请求头
     * @param {string} body - 请求体
     * @returns {Object} - 检测结果
     */
    detectFileUpload(path, method, headers, body) {
        // 文件上传漏洞特征
        const fileUploadPatterns = [
            // 文件名中包含可执行扩展名
            /\.(php|asp|aspx|jsp|js|exe|bat|cmd|sh|pl|py|cgi|dll|so)$/i,
            // 路径中包含文件上传关键字
            /upload|file|image|avatar|document|attachment/i,
            // 包含危险的文件上传参数名
            /file|upload|image|avatar|document|attachment/i
        ];

        // 检查请求方法是否为POST或PUT
        if (method !== 'POST' && method !== 'PUT') {
            return { isThreat: false };
        }

        // 检查Content-Type
        const contentType = headers['Content-Type'] || '';
        if (!contentType.includes('multipart/form-data')) {
            return { isThreat: false };
        }

        // 检查路径是否包含文件上传关键字
        for (const pattern of fileUploadPatterns) {
            if (pattern.test(path)) {
                return {
                    isThreat: true,
                    type: 'file_upload',
                    message: '检测到文件上传漏洞特征',
                    evidence: path
                };
            }
        }

        return { isThreat: false };
    }

    /**
     * 检测跨站脚本攻击(XSS)
     * @param {string} path - URL路径
     * @param {string} body - 请求体
     * @returns {Object} - 检测结果
     */
    detectXss(path, body) {
        // XSS特征模式
        const xssPatterns = [
            // HTML标签特征
            /<script[^>]*>.*<\/script>/i,
            /<iframe[^>]*>.*<\/iframe>/i,
            /<object[^>]*>.*<\/object>/i,
            /<embed[^>]*>/i,
            /<applet[^>]*>.*<\/applet>/i,
            /<meta[^>]*>/i,
            /<link[^>]*>/i,
            /<style[^>]*>.*<\/style>/i,
            /<img[^>]*>/i,
            /<svg[^>]*>.*<\/svg>/i,
            // 事件处理器特征
            /onload|onerror|onclick|onmouseover|onkeydown|onkeyup|onfocus|onblur|onchange|onresize|onscroll/i,
            // JavaScript伪协议
            /javascript:/i,
            // VBScript伪协议
            /vbscript:/i,
            // 表达式语言
            /\$\{.*\}/,
            /%\{.*\}/,
            // HTML编码特征
            /&#x?[0-9a-fA-F]+;/i,
            /&[a-zA-Z]+;/i
        ];

        // 合并所有待检测的字符串
        const combined = [path, body].join(' ');
        
        // 检测每个模式
        for (const pattern of xssPatterns) {
            if (pattern.test(combined)) {
                return {
                    isThreat: true,
                    type: 'xss',
                    message: '检测到跨站脚本攻击(XSS)特征',
                    evidence: combined.match(pattern)[0]
                };
            }
        }

        return { isThreat: false };
    }

    /**
     * 检测跨站请求伪造(CSRF)
     * @param {string} method - 请求方法
     * @param {Object} headers - 请求头
     * @returns {Object} - 检测结果
     */
    detectCsrf(method, headers) {
        // CSRF检测逻辑
        const csrfPatterns = {
            // 敏感操作方法
            sensitiveMethods: ['POST', 'PUT', 'DELETE', 'PATCH'],
            // 缺少CSRF令牌的常见请求头
            missingCsrfToken: !headers['X-CSRF-Token'] && !headers['X-XSRF-Token'] && !headers['CSRF-Token'],
            // 缺少Referer或Origin头
            missingOrigin: !headers['Origin'] && !headers['Referer']
        };

        // 只检测敏感操作方法
        if (!csrfPatterns.sensitiveMethods.includes(method)) {
            return { isThreat: false };
        }

        // 检测是否缺少CSRF保护
        if (csrfPatterns.missingCsrfToken && csrfPatterns.missingOrigin) {
            return {
                isThreat: true,
                type: 'csrf',
                message: '检测到跨站请求伪造(CSRF)风险：缺少CSRF令牌和Origin/Referer头',
                evidence: `Method: ${method}, Missing CSRF Token: ${csrfPatterns.missingCsrfToken}, Missing Origin/Referer: ${csrfPatterns.missingOrigin}`
            };
        }

        return { isThreat: false };
    }

    /**
     * 检测路径遍历漏洞
     * @param {string} path - URL路径
     * @returns {Object} - 检测结果
     */
    detectPathTraversal(path) {
        // 路径遍历特征模式
        const pathTraversalPatterns = [
            /\.\./i, // ../
            /%2e%2e/i, // URL编码的 ../
            /%252e%252e/i, // 双重URL编码的 ../
            /~\//, // ~/
            /\/etc\//i, // /etc/
            /\/proc\//i, // /proc/
            /\/sys\//i, // /sys/
            /\/dev\//i, // /dev/
            /\/boot\//i, // /boot/
            /\/usr\//i, // /usr/
            /\/var\//i, // /var/
            /\/opt\//i, // /opt/
            /\/home\//i, // /home/
            /\/root\//i // /root/
        ];

        // 检测每个模式
        for (const pattern of pathTraversalPatterns) {
            if (pattern.test(path)) {
                return {
                    isThreat: true,
                    type: 'path_traversal',
                    message: '检测到路径遍历漏洞特征',
                    evidence: path.match(pattern)[0]
                };
            }
        }

        return { isThreat: false };
    }

    /**
     * 检测命令注入漏洞
     * @param {string} path - URL路径
     * @param {string} body - 请求体
     * @returns {Object} - 检测结果
     */
    detectCommandInjection(path, body) {
        // 命令注入特征模式
        const commandPatterns = [
            /(\;|\|\||\||\&\&|\&|\`|\$\(|eval|exec|system|shell_exec|passthru|popen|proc_open)/i,
            /(cat|ls|dir|whoami|id|pwd|uname|env|ip|ifconfig|netstat|ps|kill|rm|cp|mv|mkdir|rmdir|touch|chmod|chown|ping|nc|ncat|telnet|ssh|wget|curl)/i
        ];

        // 合并所有待检测的字符串
        const combined = [path, body].join(' ');
        
        // 检测每个模式
        for (const pattern of commandPatterns) {
            if (pattern.test(combined)) {
                return {
                    isThreat: true,
                    type: 'command_injection',
                    message: '检测到命令注入攻击特征',
                    evidence: combined.match(pattern)[0]
                };
            }
        }

        return { isThreat: false };
    }

    /**
     * 检测敏感信息泄露
     * @param {string} path - URL路径
     * @param {string} body - 请求体
     * @returns {Object} - 检测结果
     */
    detectSensitiveInfoLeak(path, body) {
        // 敏感信息特征模式
        const sensitivePatterns = [
            /(password|passwd|pwd|secret|key|token|api_key|access_token|auth_token|session|cookie|credit_card|cc_number|ssn|social_security|bank_account|id_card|身份证|银行卡|手机号|phone|email|邮箱)/i,
            /(admin|root|manager|superuser|administrator|system|backup|restore|debug|test|demo|dev|development|staging|internal)/i,
            /(\.git|\.svn|\.hg|\.bzr|\.DS_Store|Thumbs\.db|README|CHANGELOG|LICENSE|package\.json|package-lock\.json|yarn\.lock|composer\.json|requirements\.txt|setup\.py|Makefile|CMakeLists\.txt)/i,
            /(error|exception|stacktrace|traceback|debug|warning|notice|fatal|critical|alert|emergency)/i
        ];

        // 合并所有待检测的字符串
        const combined = [path, body].join(' ');
        
        // 检测每个模式
        for (const pattern of sensitivePatterns) {
            if (pattern.test(combined)) {
                return {
                    isThreat: true,
                    type: 'sensitive_info_leak',
                    message: '检测到敏感信息泄露风险',
                    evidence: combined.match(pattern)[0]
                };
            }
        }

        return { isThreat: false };
    }

    /**
     * 检测HTTP参数污染漏洞
     * @param {string} path - URL路径
     * @returns {Object} - 检测结果
     */
    detectHttpParameterPollution(path) {
        // HTTP参数污染特征：同一参数出现多次
        const paramRegex = /([?&])([^=]+)=([^&]+)/g;
        const params = {};
        let match;
        
        while ((match = paramRegex.exec(path)) !== null) {
            const paramName = match[2];
            if (params[paramName]) {
                return {
                    isThreat: true,
                    type: 'http_parameter_pollution',
                    message: '检测到HTTP参数污染漏洞特征',
                    evidence: `${paramName}参数出现多次`
                };
            }
            params[paramName] = match[3];
        }

        return { isThreat: false };
    }

    /**
     * 检测JSON注入漏洞
     * @param {string} body - 请求体
     * @returns {Object} - 检测结果
     */
    detectJsonInjection(body) {
        // JSON注入特征模式
        const jsonPatterns = [
            /(\}|\{).*(\}|\{)/,
            /(\[|\]).*(\[|\])/,
            /(true|false|null).*(true|false|null)/i
        ];

        // 检测每个模式
        for (const pattern of jsonPatterns) {
            if (pattern.test(body)) {
                return {
                    isThreat: true,
                    type: 'json_injection',
                    message: '检测到JSON注入攻击特征',
                    evidence: body.match(pattern)[0]
                };
            }
        }

        return { isThreat: false };
    }

    /**
     * 检测XML注入漏洞
     * @param {string} body - 请求体
     * @returns {Object} - 检测结果
     */
    detectXmlInjection(body) {
        // XML注入特征模式
        const xmlPatterns = [
            /(<!DOCTYPE|<!ENTITY|\%|]>)/i,
            /(<\?xml|\?>|<\/|<\w+>)/i
        ];

        // 检测每个模式
        for (const pattern of xmlPatterns) {
            if (pattern.test(body)) {
                return {
                    isThreat: true,
                    type: 'xml_injection',
                    message: '检测到XML注入攻击特征',
                    evidence: body.match(pattern)[0]
                };
            }
        }

        return { isThreat: false };
    }

    /**
     * 检测SSRF(服务器端请求伪造)漏洞
     * @param {string} path - URL路径
     * @param {Object} headers - 请求头
     * @returns {Object} - 检测结果
     */
    detectSsrf(path, headers) {
        // SSRF特征模式
        const ssrfPatterns = [
            /(http:\/\/|https:\/\/|ftp:\/\/|file:\/\/|gopher:\/\/|sftp:\/\/|telnet:\/\/|dict:\/\/|ldap:\/\/|ldaps:\/\/|mysql:\/\/|postgres:\/\/|mongodb:\/\/|redis:\/\/)/i,
            /(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.1[6-9]\.\d{1,3}\.\d{1,3}|172\.2\d\.\d{1,3}\.\d{1,3}|172\.3[01]\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/i
        ];

        // 检查URL路径
        for (const pattern of ssrfPatterns) {
            if (pattern.test(path)) {
                return {
                    isThreat: true,
                    type: 'ssrf',
                    message: '检测到SSRF(服务器端请求伪造)攻击特征',
                    evidence: path.match(pattern)[0]
                };
            }
        }

        // 检查请求头
        for (const [headerName, headerValue] of Object.entries(headers)) {
            const headerStr = String(headerValue);
            for (const pattern of ssrfPatterns) {
                if (pattern.test(headerStr)) {
                    return {
                        isThreat: true,
                        type: 'ssrf',
                        message: `检测到SSRF(服务器端请求伪造)攻击特征 - 来自${headerName}头`,
                        evidence: headerStr.match(pattern)[0]
                    };
                }
            }
        }

        return { isThreat: false };
    }

    /**
     * 获取威胁类型的中文描述
     * @param {string} threatType - 威胁类型
     * @returns {string} - 中文描述
     */
    getThreatDescription(threatType) {
        const descriptions = {
            'sql_injection': 'SQL注入',
            'file_upload': '文件上传漏洞',
            'xss': '跨站脚本攻击(XSS)',
            'csrf': '跨站请求伪造(CSRF)',
            'path_traversal': '路径遍历漏洞',
            'command_injection': '命令注入',
            'sensitive_info_leak': '敏感信息泄露',
            'http_parameter_pollution': 'HTTP参数污染',
            'json_injection': 'JSON注入',
            'xml_injection': 'XML注入',
            'ssrf': '服务器端请求伪造(SSRF)'
        };
        return descriptions[threatType] || '未知威胁';
    }
}

// 创建全局实例
const securityDetector = new SecurityDetector();

// 导出模块
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SecurityDetector, securityDetector };
}