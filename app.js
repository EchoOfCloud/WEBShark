let currentPackets = [];
let originalPackets = []; // 保存原始数据包列表，用于筛选
let currentStats = null;
let currentStreams = {};
let originalStreams = {}; // 保存原始流列表，用于筛选
let currentTiming = null; // 保存分析时间统计数据
let currentPacketIndex = -1; // 记录当前数据包索引
// 系统默认关键字常量
const DEFAULT_KEYWORDS = ['flag', 'fl', 'KEY', 'pass', 'user', 'select', 'ctf', '@eval', 'frpc', 'linux', 'login', 'log', '.log', 'whoami', 'echo', 'admin', 'xss', 'alter'];
// 当前关键字列表，用于数据包匹配
let keywords = [...DEFAULT_KEYWORDS];

// 排序相关变量
let currentSortField = null;
let currentSortDirection = 'asc'; // 'asc' 或 'desc'

// 全局缓存：用于快速查找数据包
let packetIdMap = new Map();
// 全局缓存：用于存储请求和响应的映射关系
let responseCache = new Map();

// 更新数据包ID缓存
function updatePacketIdMap() {
    packetIdMap.clear();
    originalPackets.forEach(packet => {
        packetIdMap.set(packet.uniqueId, packet);
    });
}

// 清空响应缓存
function clearResponseCache() {
    responseCache.clear();
}

// 预计算并缓存常用的统计信息
function precomputeAndCacheStats() {
    console.log('开始预计算并缓存统计信息...');
    
    // 1. 预计算并缓存流的统计信息
    Object.values(originalStreams).forEach(stream => {
        // 预计算并缓存流的总长度
        const streamPackets = getStreamPackets(stream);
        const totalLength = streamPackets.reduce((sum, packet) => {
            return sum + (packet.packetLen || 0);
        }, 0);
        stream._cachedTotalLength = totalLength;
        
        // 预计算并缓存流的主要协议
        let protocol = 'Unknown';
        if (streamPackets.length > 0) {
            const appProtocols = streamPackets
                .filter(packet => packet.layers?.application)
                .map(packet => packet.layers.application.protocol)
                .filter(Boolean)
                .filter(protocol => protocol !== 'Unknown');
            
            if (appProtocols.length > 0) {
                const protocolCounts = appProtocols.reduce((acc, curr) => {
                    acc[curr] = (acc[curr] || 0) + 1;
                    return acc;
                }, {});
                
                protocol = Object.entries(protocolCounts)
                    .sort(([,a], [,b]) => b - a)
                    [0][0];
            } else {
                protocol = streamPackets[0].protocol;
            }
        }
        stream._cachedProtocol = protocol;
    });
    
    // 2. 预缓存所有HTTP请求-响应映射关系
    originalPackets.forEach(packet => {
        if (packet.layers?.application?.httpInfo && packet.layers.application.httpInfo.method) {
            // 这是一个HTTP请求，预计算并缓存其响应
            getHttpResponseForRequest(packet);
        }
        // 对于非HTTP请求，也预计算并缓存其响应
        else if (packet.layers?.application && packet.layers.application.protocol && packet.layers.application.protocol !== 'Unknown') {
            getNonHttpResponseForRequest(packet);
        }
    });
    
    console.log('完成流统计信息和请求-响应映射关系的预计算和缓存');
}

// 辅助函数：根据唯一ID获取完整的数据包对象
function getPacketById(packetId) {
    return packetIdMap.get(packetId) || null;
}

// 辅助函数：获取流中所有完整的数据包对象
function getStreamPackets(stream) {
    // 如果已经缓存了结果，直接返回
    if (stream._cachedPackets) {
        return stream._cachedPackets;
    }
    // 计算结果并缓存
    const packets = stream.packets.map(packetId => getPacketById(packetId)).filter(packet => packet !== null);
    stream._cachedPackets = packets;
    return packets;
}

// 分页相关变量
let currentPage = 1; // 当前页码
let pageSize = 100; // 每页显示数量
let totalPages = 1; // 总页数
let currentListType = 'packets'; // 当前显示的列表类型：'packets', 'streams', 'appRequests'

// 表格列宽拖拽功能
let isResizing = false;
let currentTable = null;
let currentColumn = null;
let startX = 0;
let startWidth = 0;

// 筛选功能相关变量
let currentFilterDropdown = null;
let currentFilterColumn = null;
let currentFilterTable = null;
let filters = {}; // 存储各表格的筛选条件，格式：{ tableId: { columnIndex: [values] } }

// 初始化表格列宽拖拽功能和筛选功能
if (typeof window !== 'undefined' && window.document) {
    document.addEventListener('DOMContentLoaded', function() {
        initTableResizable();
        initTableFilters();
        initSettings(); // 初始化关键字设置
        
        // 为所有输入框添加事件监听器，防止反向输入
        const allInputs = document.querySelectorAll('input[type="text"]');
        allInputs.forEach(input => {
            // 确保初始状态正确
            input.setAttribute('dir', 'ltr');
            input.style.direction = 'ltr';
            input.style.textAlign = 'left';
            input.style.unicodeBidi = 'bidi-override';
            
            // 添加事件监听器，确保在任何情况下都保持正确的文本方向
            input.addEventListener('focus', function() {
                this.setAttribute('dir', 'ltr');
                this.style.direction = 'ltr';
                this.style.textAlign = 'left';
                this.style.unicodeBidi = 'bidi-override';
            });
            
            input.addEventListener('input', function() {
                this.setAttribute('dir', 'ltr');
                this.style.direction = 'ltr';
                this.style.textAlign = 'left';
                this.style.unicodeBidi = 'bidi-override';
            });
            
            input.addEventListener('keydown', function() {
                this.setAttribute('dir', 'ltr');
                this.style.direction = 'ltr';
                this.style.textAlign = 'left';
                this.style.unicodeBidi = 'bidi-override';
            });
            
            input.addEventListener('paste', function() {
                // 粘贴后确保文本方向正确
                setTimeout(() => {
                    this.setAttribute('dir', 'ltr');
                    this.style.direction = 'ltr';
                    this.style.textAlign = 'left';
                    this.style.unicodeBidi = 'bidi-override';
                }, 0);
            });
        });
        
        // 监听动态创建的输入框
        document.addEventListener('DOMNodeInserted', function(e) {
            if (e.target.tagName === 'INPUT' && e.target.type === 'text') {
                const input = e.target;
                // 确保动态创建的输入框也有正确的设置
                input.setAttribute('dir', 'ltr');
                input.style.direction = 'ltr';
                input.style.textAlign = 'left';
                input.style.unicodeBidi = 'bidi-override';
                
                // 添加相同的事件监听器
                input.addEventListener('focus', function() {
                    this.setAttribute('dir', 'ltr');
                    this.style.direction = 'ltr';
                    this.style.textAlign = 'left';
                    this.style.unicodeBidi = 'bidi-override';
                });
                
                input.addEventListener('input', function() {
                    this.setAttribute('dir', 'ltr');
                    this.style.direction = 'ltr';
                    this.style.textAlign = 'left';
                    this.style.unicodeBidi = 'bidi-override';
                });
                
                input.addEventListener('keydown', function() {
                    this.setAttribute('dir', 'ltr');
                    this.style.direction = 'ltr';
                    this.style.textAlign = 'left';
                    this.style.unicodeBidi = 'bidi-override';
                });
                
                input.addEventListener('paste', function() {
                    // 粘贴后确保文本方向正确
                    setTimeout(() => {
                        this.setAttribute('dir', 'ltr');
                        this.style.direction = 'ltr';
                        this.style.textAlign = 'left';
                        this.style.unicodeBidi = 'bidi-override';
                    }, 0);
                });
            }
        });
    });
}

// 重新初始化表格列宽拖拽功能，用于动态生成的表格
function reinitTableResizable() {
    stopResizing();
    initTableResizable();
    // 重新初始化筛选功能
    initTableFilters();
}

// 初始化表格筛选功能
function initTableFilters() {
    // 检查是否在浏览器环境中
    if (typeof document === 'undefined') {
        return;
    }
    
    // 为所有表格添加筛选功能
    const tables = document.querySelectorAll('.packets-table');
    tables.forEach(table => {
        const headers = table.querySelectorAll('th');
        headers.forEach((header, index) => {
            // 跳过操作列
            const headerText = header.textContent.trim();
            if (headerText === '操作') {
                return;
            }
            
            // 如果已经有筛选图标，移除它
            const existingFilterIcon = header.querySelector('.filter-icon');
            if (existingFilterIcon) {
                existingFilterIcon.remove();
            }
            
            // 添加筛选图标
            const filterIcon = document.createElement('span');
            filterIcon.className = 'filter-icon';
            filterIcon.textContent = '▼';
            filterIcon.setAttribute('data-column', index);
            filterIcon.setAttribute('data-table-id', table.id);
            
            // 添加点击事件
            filterIcon.addEventListener('click', function(e) {
                e.stopPropagation();
                toggleFilterDropdown(e, header, index, table);
            });
            
            header.appendChild(filterIcon);
        });
    });
    
    // 添加全局点击事件，点击其他地方关闭筛选下拉菜单
    document.addEventListener('click', function(e) {
        if (currentFilterDropdown && !e.target.closest('.filter-dropdown') && !e.target.classList.contains('filter-icon')) {
            closeFilterDropdown();
        }
    });
}

// 切换筛选下拉菜单显示/隐藏
function toggleFilterDropdown(e, header, columnIndex, table) {
    // 关闭现有下拉菜单
    closeFilterDropdown();
    
    // 获取当前表格的数据
    const tableId = table.id;
    let data = [];
    
    // 根据表格类型获取数据
    if (tableId === 'appRequestsTable') {
        // 应用层请求列表（只显示请求，不显示响应）
        data = originalPackets.filter(packet => {
            return packet.layers?.application && 
                   packet.layers.application.protocol &&
                   packet.layers.application.protocol !== 'Unknown' &&
                   // 只保留请求：HTTP请求有method字段，响应有statusCode字段
                   (packet.layers.application.httpInfo ? 
                    packet.layers.application.httpInfo.method !== undefined && 
                    packet.layers.application.httpInfo.statusCode === undefined : 
                    true);
        });
    } else if (tableId === 'packetsTable') {
        // 数据包列表 - 使用当前过滤后的数据包，而不是原始数据包
        data = currentPackets;
    } else if (tableId === 'flowsTable') {
        // 流列表 - 使用完整的原始流数据，确保筛选条件完整
        data = Object.values(originalStreams || currentStreams);
    } else if (tableId === 'ipPortStatsTable') {
        // IP端口统计列表 - 使用当前过滤后的数据包来生成统计数据
        data = originalPackets; // 使用原始数据包，确保有数据
        console.log('IP Port Stats Data Length:', data.length);
    }
    
    // 检查数据是否为空
    if (data.length === 0) {
        console.warn('No data available for filtering');
        return;
    }
    
    // 获取当前列的所有唯一值
    let uniqueValues = getUniqueColumnValues(data, columnIndex, tableId);
    
    // 检查当前列是否有筛选条件
    const tableFilters = filters[tableId] || {};
    const columnFilters = tableFilters[columnIndex] || [];
    
    // 如果当前列有筛选条件，确保筛选值在唯一值列表中
    if (columnFilters.length > 0) {
        const uniqueValuesSet = new Set(uniqueValues.map(item => item.value));
        
        // 添加缺失的筛选值到唯一值列表
        columnFilters.forEach(filterValue => {
            if (!uniqueValuesSet.has(filterValue)) {
                uniqueValues.push({ value: filterValue, count: 0 });
                uniqueValuesSet.add(filterValue);
            }
        });
        
        // 重新排序
        uniqueValues.sort((a, b) => a.value.localeCompare(b.value));
    }
    
    // 创建筛选下拉菜单
    const dropdown = createFilterDropdown(uniqueValues, tableId, columnIndex);
    
    // 定位下拉菜单
    const rect = header.getBoundingClientRect();
    // 检查是否在浏览器环境中
    if (typeof window !== 'undefined') {
        dropdown.style.left = `${rect.left + window.scrollX}px`;
        dropdown.style.top = `${rect.bottom + window.scrollY}px`;
    } else {
        dropdown.style.left = `${rect.left}px`;
        dropdown.style.top = `${rect.bottom}px`;
    }
    
    // 添加到文档
    document.body.appendChild(dropdown);
    
    // 保存当前状态
    currentFilterDropdown = dropdown;
    currentFilterColumn = columnIndex;
    currentFilterTable = table;
}

// 获取指定列的所有唯一值及其出现次数
function getUniqueColumnValues(data, columnIndex, tableId) {
    const valueCounts = {};
    
    data.forEach(item => {
        let value;
        
        // 根据表格类型和列索引获取值
        if (tableId === 'appRequestsTable') {
                // 应用层请求列表
                switch(columnIndex) {
                    case 0: value = item.uniqueId || '-'; break; // 序号
                    case 1: {
                        // 请求方法或协议名称
                        if (item.layers.application.httpInfo) {
                            value = item.layers.application.httpInfo.method || '-';
                        } else {
                            value = item.layers.application.protocol || '-';
                        }
                        break;
                    } // 请求方法/协议
                    case 2: {
                        // URL路径或信息
                        if (item.layers.application.httpInfo) {
                            value = urlDecode(item.layers.application.httpInfo.path || '') || '-';
                        } else {
                            value = item.layers.application.rawInfo || item.layers.application.info || '-';
                        }
                        break;
                    } // 路径/信息
                    case 3: {
                        // 协议版本
                        value = item.layers.application.httpInfo?.version || 'Unknown';
                        break;
                    } // 协议版本
                case 4: value = `${item.srcIp}:${item.layers?.transport?.srcPort || '-'}`; break; // 源IP:端口
                case 5: value = `${item.dstIp}:${item.layers?.transport?.dstPort || '-'}`; break; // 目标IP:端口
                case 6: {
                    const responsePacket = item.layers.application.httpInfo ? getHttpResponseForRequest(item) : null;
                    if (responsePacket?.layers?.application?.httpInfo?.statusCode) {
                        const statusCode = responsePacket.layers.application.httpInfo.statusCode;
                        const statusText = responsePacket.layers.application.httpInfo.statusText || '';
                        value = `${statusCode} ${statusText}`;
                    } else {
                        value = '-';
                    }
                    break;
                } // 响应状态
                case 7: {
                    // 响应大小
                    const isHttp = !!item.layers.application.httpInfo;
                    const httpInfo = item.layers.application.httpInfo;
                    let responseSize = '-';
                    
                    if (isHttp) {
                        // HTTP协议处理
                        const responsePacket = getHttpResponseForRequest(item);
                        if (responsePacket) {
                            responseSize = `${responsePacket.packetLen} bytes`;
                        } else if (httpInfo.headers?.['Content-Length']) {
                            responseSize = `${httpInfo.headers['Content-Length']} bytes`;
                        }
                    } else {
                        // 非HTTP协议处理
                        const responsePacketNonHttp = getNonHttpResponseForRequest(item);
                        if (responsePacketNonHttp) {
                            responseSize = `${responsePacketNonHttp.packetLen} bytes`;
                        } else {
                            responseSize = `${item.packetLen} bytes`;
                        }
                    }
                    value = responseSize;
                    break;
                } // 响应大小
                case 8: value = item.layers.application.httpInfo?.headers?.Host || '-'; break; // Host
                case 9: value = item.layers.application.httpInfo?.headers?.['User-Agent'] || '-'; break; // User-Agent
                case 10: value = item.layers.application.httpInfo?.headers?.Accept || '-'; break; // Accept
                case 11: value = item.layers.application.httpInfo?.headers?.['Accept-Language'] || '-'; break; // Accept-Language
                case 12: value = item.layers.application.httpInfo?.headers?.Cookie || '-'; break; // Cookie
                case 13: value = item.layers.application.httpInfo?.headers?.['Content-Type'] || '-'; break; // Content-Type
                case 14: {
                    const responsePacket = item.layers.application.httpInfo ? getHttpResponseForRequest(item) : null;
                    value = responsePacket?.layers?.application?.httpInfo?.headers?.['Content-Type'] || '-';
                    break;
                } // 响应内容类型
                case 15: {
                    const responsePacket = item.layers.application.httpInfo ? getHttpResponseForRequest(item) : null;
                    value = responsePacket?.layers?.application?.httpInfo?.headers?.Server || '-';
                    break;
                } // 服务器
                case 16: {
                    const responsePacket = item.layers.application.httpInfo ? getHttpResponseForRequest(item) : null;
                    value = responsePacket ? `${(responsePacket.timestamp - item.timestamp).toFixed(3)}s` : '-';
                    break;
                } // 响应时间
                case 17: {
                    // 请求体内容 - 只显示前50个字符用于筛选
                    let requestBody = '-';
                    if (item.layers.application.httpInfo?.body) {
                        requestBody = item.layers.application.httpInfo.body;
                    } else if (item.layers.application.raw) {
                        requestBody = item.layers.application.raw;
                    }
                    if (requestBody && requestBody.length > 50) {
                        requestBody = requestBody.substring(0, 50) + '...';
                    }
                    value = requestBody;
                    break;
                } // 请求体内容
                case 18: {
                    // 响应体内容 - 只显示前50个字符用于筛选
                    let responseBody = '-';
                    const responsePacket = item.layers.application.httpInfo ? getHttpResponseForRequest(item) : null;
                    if (responsePacket?.layers?.application?.httpInfo?.raw) {
                        const rawResponse = responsePacket.layers.application.httpInfo.raw;
                        const parts = rawResponse.split(/\r?\n\r?\n/);
                        if (parts.length > 1) {
                            responseBody = parts.slice(1).join('\r\n\r\n');
                            if (responseBody.length > 50) {
                                responseBody = responseBody.substring(0, 50) + '...';
                            }
                        }
                    } else if (responsePacket?.layers?.application?.raw) {
                        responseBody = responsePacket.layers.application.raw;
                        if (responseBody.length > 50) {
                            responseBody = responseBody.substring(0, 50) + '...';
                        }
                    }
                    value = responseBody;
                    break;
                } // 响应体内容
                case 19: {
                    // 安全状态 - 执行安全检测获取状态
                    const securityResult = securityDetector.detect(item);
                    value = securityResult.isSecure ? '安全' : '危险';
                    break;
                } // 安全状态
                default: value = '-';
            }
            
            // 添加值到统计中
            if (value !== undefined && value !== null) {
                if (valueCounts[value]) {
                    valueCounts[value]++;
                } else {
                    valueCounts[value] = 1;
                }
            }
        } else if (tableId === 'packetsTable') {
            // 数据包列表
            switch(columnIndex) {
                case 1: value = item.uniqueId || '-'; break; // 唯一ID
                case 2: value = `${item.index + 1}` || '-'; break; // 序号
                case 3: value = PcapngParser.formatTime(item.timestamp, true) || '-'; break; // 时间
                case 4: value = item.srcIp || '-'; break; // 源IP
                case 5: value = (item.layers?.transport?.srcPort || '-').toString(); break; // 源端口
                case 6: value = item.dstIp || '-'; break; // 目标IP
                case 7: value = (item.layers?.transport?.dstPort || '-').toString(); break; // 目标端口
                case 8: value = item.protocolChain || '-'; break; // 协议链
                case 9: value = (item.streamId || '-').toString(); break; // 流ID
                case 10: value = (item.packetLen || '-').toString(); break; // 长度
                case 11: value = getPacketFunctionDescription(item) || '-'; break; // 功能介绍
                case 12: value = item.info || '-'; break; // 信息
                case 13: {
                    // 关键字匹配列
                    // 检查数据包是否匹配关键字
                    let matches = [];
                    
                    // 定义需要检查的数据包属性
                    const packetAttributes = [
                        { name: 'uniqueId', value: item.uniqueId },
                        { name: 'srcIp', value: item.srcIp },
                        { name: 'srcPort', value: item.layers?.transport?.srcPort },
                        { name: 'dstIp', value: item.dstIp },
                        { name: 'dstPort', value: item.layers?.transport?.dstPort },
                        { name: 'protocol', value: item.protocol },
                        { name: 'protocolChain', value: item.protocolChain },
                        { name: 'info', value: item.info },
                        { name: 'functionDesc', value: getPacketFunctionDescription(item) },
                        { name: 'timestamp', value: item.timestamp },
                        { name: 'packetLen', value: item.packetLen },
                        { name: 'streamId', value: item.streamId }
                    ];
                    
                    // 检查应用层数据
                    if (item.layers?.application) {
                        const appData = item.layers.application;
                        packetAttributes.push(
                            { name: 'applicationProtocol', value: appData.protocol },
                            { name: 'applicationInfo', value: appData.info },
                            { name: 'httpMethod', value: appData.httpInfo?.method },
                            { name: 'httpUrl', value: appData.httpInfo?.url },
                            { name: 'httpHeaders', value: JSON.stringify(appData.httpInfo?.headers) },
                            { name: 'httpBody', value: appData.httpInfo?.body },
                            { name: 'httpStatus', value: appData.httpInfo?.status },
                            { name: 'rawData', value: appData.raw }
                        );
                    }
                    
                    // 检查传输层数据
                    if (item.layers?.transport) {
                        const transportData = item.layers.transport;
                        packetAttributes.push(
                            { name: 'transportType', value: transportData.type },
                            { name: 'transportInfo', value: transportData.info }
                        );
                    }
                    
                    // 检查网络层数据
                    if (item.layers?.network) {
                        const networkData = item.layers.network;
                        packetAttributes.push(
                            { name: 'networkVersion', value: networkData.version },
                            { name: 'networkInfo', value: networkData.info }
                        );
                    }
                    
                    // 检查链路层数据
                    if (item.layers?.link) {
                        const linkData = item.layers.link;
                        packetAttributes.push(
                            { name: 'linkType', value: linkData.type },
                            { name: 'linkInfo', value: linkData.info }
                        );
                    }
                    
                    // 遍历所有属性和关键字，检查是否匹配（仅当开关开启时）
                    if (isKeywordMatchingEnabled()) {
                        packetAttributes.forEach(attr => {
                            if (attr.value === null || attr.value === undefined || attr.value === '-') {
                                return;
                            }
                            
                            const attrValue = String(attr.value).toLowerCase();
                            
                            keywords.forEach(keyword => {
                                const keywordLower = keyword.toLowerCase();
                                if (attrValue.includes(keywordLower)) {
                                    matches.push(keyword);
                                }
                            });
                        });
                    }
                    
                    // 去重并排序
                    matches = [...new Set(matches)].sort();
                    value = matches.length > 0 ? matches.join(', ') : '-';
                    break;
                } // 关键字匹配
                default: return; // 跳过其他列，如操作列
            }
            
            // 添加值到统计中
            if (value !== undefined && value !== null) {
                if (valueCounts[value]) {
                    valueCounts[value]++;
                } else {
                    valueCounts[value] = 1;
                }
            }
        } else if (tableId === 'flowsTable') {
        // 流列表
        switch(columnIndex) {
            case 0: value = item.id || '-'; break; // 流ID
            case 1: value = `${item.srcIp}:${item.srcPort}`; break; // 源IP:端口
            case 2: value = `${item.dstIp}:${item.dstPort}`; break; // 目标IP:端口
            case 3: {
                // 获取流的实际数据包对象
                const streamPackets = getStreamPackets(item);
                value = streamPackets.length.toString() || '-';
                break;
            } // 数据包数量
            case 4: {
                // 动态计算流的总长度，与updateStreamsList中的逻辑保持一致
                const streamPackets = getStreamPackets(item);
                const totalLength = streamPackets ? streamPackets.reduce((sum, packet) => sum + (packet.packetLen || 0), 0) : '-';
                value = totalLength.toString();
                break;
            } // 长度
            case 5: {
                // 确定流的主要协议，与updateStreamsList中的逻辑保持一致
                let protocol = 'Unknown';
                const streamPackets = getStreamPackets(item);
                if (streamPackets.length > 0) {
                    const appProtocols = streamPackets
                        .filter(packet => packet.layers?.application)
                        .map(packet => packet.layers.application.protocol)
                        .filter(Boolean)
                        .filter(protocol => protocol !== 'Unknown'); // 排除Unknown协议
                    
                    // 找出出现次数最多的协议
                    if (appProtocols.length > 0) {
                        const protocolCounts = appProtocols.reduce((acc, curr) => {
                            acc[curr] = (acc[curr] || 0) + 1;
                            return acc;
                        }, {});
                        
                        protocol = Object.entries(protocolCounts)
                            .sort(([,a], [,b]) => b - a)
                            [0][0];
                    } else {
                        protocol = streamPackets[0].protocol;
                    }
                }
                value = protocol || '-';
                break;
            } // 协议
            case 6: value = '-'; break; // 协议统计列，不用于筛选
            default: return; // 跳过其他列
        }
        
        // 添加值到统计中
        if (value && value !== '-') {
            if (valueCounts[value]) {
                valueCounts[value]++;
            } else {
                valueCounts[value] = 1;
            }
        }
        } else if (tableId === 'ipPortStatsTable') {
            // IP端口统计列表
            // 从数据包中提取IP和端口信息
            const ipPortValues = [];
            
            switch(columnIndex) {
                case 0: 
                    // IP地址列 - 收集所有源IP和目标IP
                    if (item.srcIp) {
                        ipPortValues.push(item.srcIp);
                    }
                    if (item.dstIp && item.dstIp !== item.srcIp) {
                        ipPortValues.push(item.dstIp);
                    }
                    break;
                case 1: 
                    // 归属地列 - 基于IP地址
                    if (item.srcIp) {
                        ipPortValues.push(getIpLocation(item.srcIp));
                    }
                    if (item.dstIp && item.dstIp !== item.srcIp) {
                        ipPortValues.push(getIpLocation(item.dstIp));
                    }
                    break;
                case 2: 
                    // 端口列 - 收集所有源端口和目标端口
                    if (item.layers?.transport?.srcPort) {
                        ipPortValues.push(item.layers.transport.srcPort.toString());
                    }
                    if (item.layers?.transport?.dstPort) {
                        ipPortValues.push(item.layers.transport.dstPort.toString());
                    }
                    break;
                case 3: 
                    // 端口描述列 - 基于端口
                    if (item.layers?.transport?.srcPort) {
                        ipPortValues.push(getPortDescription(item.layers.transport.srcPort.toString()));
                    }
                    if (item.layers?.transport?.dstPort) {
                        ipPortValues.push(getPortDescription(item.layers.transport.dstPort.toString()));
                    }
                    break;
                case 4: 
                    // 数据包数量列 - 使用与实际数据计算相同的逻辑
                    // 调用现有的calculateIpPortStats函数，确保使用相同的数据和统计逻辑
                    const actualIpPortStats = calculateIpPortStats();
                    // 收集唯一的数据包数量值
                    Object.values(actualIpPortStats).forEach(count => {
                        const countStr = count.toString();
                        if (valueCounts[countStr]) {
                            valueCounts[countStr]++;
                        } else {
                            valueCounts[countStr] = 1;
                        }
                    });
                    break;
                case 5: 
                    // 占比列 - 使用与实际数据计算相同的逻辑
                    const ipPortStatsForPercent = calculateIpPortStats();
                    const totalCountForPercent = Object.values(ipPortStatsForPercent).reduce((sum, count) => sum + count, 0);
                    if (totalCountForPercent > 0) {
                        // 计算每个IP+端口组合的占比，与实际显示格式保持一致（带百分号）
                        Object.values(ipPortStatsForPercent).forEach(count => {
                            const percentage = ((count / totalCountForPercent) * 100).toFixed(2) + '%';
                            if (valueCounts[percentage]) {
                                valueCounts[percentage]++;
                            } else {
                                valueCounts[percentage] = 1;
                            }
                        });
                    }
                    break;
                default: 
                    // 跳过其他列
                    return;
            }
            
            // 更新计数
            ipPortValues.forEach(val => {
                if (valueCounts[val]) {
                    valueCounts[val]++;
                } else {
                    valueCounts[val] = 1;
                }
            });
        } else {
            return; // 未知表格ID，跳过
        }
    });
    
    // 转换为[{value: string, count: number}]格式并排序
    return Object.entries(valueCounts)
        .map(([value, count]) => ({ value, count }))
        .sort((a, b) => a.value.localeCompare(b.value));
}

// 创建筛选下拉菜单
function createFilterDropdown(values, tableId, columnIndex) {
    const dropdown = document.createElement('div');
    dropdown.className = 'filter-dropdown';
    
    // 设置下拉菜单为flex布局，垂直方向
    dropdown.style.display = 'flex';
    dropdown.style.flexDirection = 'column';
    
    // 添加头部
    const header = document.createElement('div');
    header.className = 'filter-dropdown-header';
    header.textContent = '筛选条件';
    dropdown.appendChild(header);
    
    // 添加值列表容器，使其可滚动
    const valuesContainer = document.createElement('div');
    valuesContainer.style.overflowY = 'auto';
    valuesContainer.style.flex = '1';
    
    // 添加值列表
    values.forEach(item => {
        const value = item.value;
        const count = item.count;
        
        const dropdownItem = document.createElement('div');
        dropdownItem.className = 'filter-dropdown-item';
        dropdownItem.setAttribute('data-value', value);
        
        // 创建值和计数的布局
        dropdownItem.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span>${value}</span>
                <span style="font-size: 11px; color: #999;">(${count})</span>
            </div>
        `;
        
        // 检查是否已经选中
        const tableFilters = filters[tableId] || {};
        const columnFilters = tableFilters[columnIndex] || [];
        if (columnFilters.includes(value)) {
            dropdownItem.classList.add('selected');
        }
        
        // 添加点击事件
        dropdownItem.addEventListener('click', function() {
            this.classList.toggle('selected');
        });
        
        valuesContainer.appendChild(dropdownItem);
    });
    
    dropdown.appendChild(valuesContainer);
    
    // 添加底部按钮
    const footer = document.createElement('div');
    footer.className = 'filter-dropdown-footer';
    // 设置底部为flex布局，左对齐
    footer.style.display = 'flex';
    footer.style.justifyContent = 'flex-start';
    footer.style.gap = '10px';
    
    const applyBtn = document.createElement('button');
    applyBtn.className = 'filter-btn';
    applyBtn.textContent = '应用';
    applyBtn.addEventListener('click', function() {
        applyFilter(tableId, columnIndex);
    });
    
    const clearBtn = document.createElement('button');
    clearBtn.className = 'filter-btn clear';
    clearBtn.textContent = '清除';
    clearBtn.addEventListener('click', function() {
        clearColumnFilter(tableId, columnIndex);
    });
    
    footer.appendChild(applyBtn);
    footer.appendChild(clearBtn);
    dropdown.appendChild(footer);
    
    return dropdown;
}

// 应用筛选条件
function applyFilter(tableId, columnIndex) {
    const selectedItems = currentFilterDropdown.querySelectorAll('.filter-dropdown-item.selected');
    const selectedValues = Array.from(selectedItems).map(item => item.getAttribute('data-value'));
    
    // 保存筛选条件
    if (!filters[tableId]) {
        filters[tableId] = {};
    }
    
    // 如果没有选择任何值，移除该列的筛选条件
    if (selectedValues.length === 0) {
        delete filters[tableId][columnIndex];
        // 如果表格没有筛选条件，删除整个表格的筛选对象
        if (Object.keys(filters[tableId]).length === 0) {
            delete filters[tableId];
        }
    } else {
        filters[tableId][columnIndex] = selectedValues;
    }
    
    // 更新筛选图标状态
    updateFilterIconState(tableId, columnIndex);
    
    // 应用筛选
    applyAllFilters();
    
    // 关闭下拉菜单
    closeFilterDropdown();
}

// 清除列筛选条件
function clearColumnFilter(tableId, columnIndex) {
    // 清除筛选条件
    if (filters[tableId]) {
        delete filters[tableId][columnIndex];
        // 如果表格没有筛选条件，删除整个表格的筛选对象
        if (Object.keys(filters[tableId]).length === 0) {
            delete filters[tableId];
        }
    }
    
    // 更新筛选图标状态
    updateFilterIconState(tableId, columnIndex);
    
    // 应用筛选
    applyAllFilters();
    
    // 关闭下拉菜单
    closeFilterDropdown();
}

// 更新筛选图标状态
function updateFilterIconState(tableId, columnIndex) {
    const table = document.getElementById(tableId);
    if (!table) return;
    
    const headers = table.querySelectorAll('th');
    const header = headers[columnIndex];
    if (!header) return;
    
    const filterIcon = header.querySelector('.filter-icon');
    if (!filterIcon) return;
    
    // 检查是否有筛选条件
    const tableFilters = filters[tableId] || {};
    const columnFilters = tableFilters[columnIndex] || [];
    
    if (columnFilters.length > 0) {
        filterIcon.classList.add('active');
        header.classList.add('filtered'); // 添加筛选后的表头样式
    } else {
        filterIcon.classList.remove('active');
        header.classList.remove('filtered'); // 移除筛选后的表头样式
    }
}

// 应用所有筛选条件
function applyAllFilters() {
    // 根据当前显示的列表类型应用筛选
    if (currentListType === 'packets') {
        filterPackets();
    } else if (currentListType === 'streams') {
        filterFlows();
    } else if (currentListType === 'appRequests') {
            searchAppRequests();
    }
    
    // 检查当前是否显示IP端口统计列表
    const ipPortStatsTab = document.getElementById('ipPortStats');
    if (ipPortStatsTab && ipPortStatsTab.classList.contains('active')) {
        // 重新生成IP端口统计列表
        const ipPortCounts = calculateIpPortStats();
        
        // 收集所有IP地址并为每个IP分配唯一颜色
        const ipColors = {};
        Object.entries(ipPortCounts).forEach(([ipPort, count]) => {
            const [ip] = ipPort.split(':');
            if (!ipColors[ip]) {
                ipColors[ip] = generateUniqueColor(ip);
            }
        });
        
        // 计算总数据包数量
        const totalPackets = currentPackets.length;
        
        // 重新生成表格
        generateIpPortStatsTable(ipPortCounts, ipColors, totalPackets);
    }
}

// 全局清除筛选函数，清除所有筛选、搜索和高级筛选条件
function clearAllFilters() {
    // 1. 清除所有表格的筛选条件
    filters = {};
    
    // 2. 清除所有搜索框内容
    const searchInputs = document.querySelectorAll('input[type="text"][id$="Search"], input[type="text"][id$="search"], input[type="text"][id="searchInput"], input[type="text"][id$="Input"]');
    searchInputs.forEach(input => {
        // 只清除搜索相关的输入框，避免清除其他可能以Input结尾的输入框
        if (input.placeholder && input.placeholder.includes('搜索')) {
            input.value = '';
        }
    });
    
    // 3. 重置全局搜索关键词变量
    currentSearchKeyword = '';
    currentFlowSearchKeyword = '';
    currentHttpSearchKeyword = '';
    
    // 4. 清除所有筛选类型选择
    const filterTypeSelects = document.querySelectorAll('select[id$="FilterType"], select[id$="filterType"], select[id="filterType"]');
    filterTypeSelects.forEach(select => {
        select.value = 'all';
    });
    
    // 4. 清除所有高级筛选条件
    const filterConditions = document.querySelectorAll('#filterConditions, #flowFilterConditions, #appRequestFilterConditions');
    filterConditions.forEach(container => {
        // 保留第一个筛选条件行，清空其他行
        const rows = container.querySelectorAll('.filter-row, .flow-filter-row, .appRequest-filter-row');
        if (rows.length > 0) {
            // 清空第一个行的值
            const firstRow = rows[0];
            const firstRowInputs = firstRow.querySelectorAll('select, input[type="text"]');
            firstRowInputs.forEach((input, index) => {
                if (index === 0) { // 第一个select（字段）
                    input.value = input.options[0].value;
                } else if (index === 1) { // 第二个select（操作符）
                    input.value = 'contains';
                } else if (index === 2) { // 输入框（值）
                    input.value = '';
                } else if (index === 3) { // 第四个select（逻辑关系）
                    input.value = 'AND';
                }
            });
            
            // 删除其他行
            for (let i = 1; i < rows.length; i++) {
                rows[i].remove();
            }
        }
    });
    
    // 5. 重置数据包列表
    currentPackets = [...originalPackets];
    currentStreams = { ...originalStreams };
    
    // 6. 重置页码
    currentPage = 1;
    
    // 7. 重置排序
    currentSortField = null;
    currentSortDirection = 'asc';
    
    // 8. 更新所有筛选图标状态
    const tables = document.querySelectorAll('.packets-table');
    tables.forEach(table => {
        const headers = table.querySelectorAll('th');
        headers.forEach((header, columnIndex) => {
            updateFilterIconState(table.id, columnIndex);
        });
    });
    
    // 9. 重新加载数据
    if (currentListType === 'packets') {
        updateListWithPagination();
    } else if (currentListType === 'streams') {
        updateStreamsList(currentStreams);
    } else if (currentListType === 'appRequests') {
        updateAppRequestsList();
    }
    
    // 10. 检查当前是否显示IP端口统计列表
    const ipPortStatsTab = document.getElementById('ipPortStats');
    if (ipPortStatsTab && ipPortStatsTab.classList.contains('active')) {
        // 重新生成IP端口统计列表
        const ipPortCounts = calculateIpPortStats();
        const ipColors = {};
        Object.entries(ipPortCounts).forEach(([ipPort, count]) => {
            const [ip] = ipPort.split(':');
            if (!ipColors[ip]) {
                ipColors[ip] = generateUniqueColor(ip);
            }
        });
        const totalPackets = currentPackets.length;
        generateIpPortStatsTable(ipPortCounts, ipColors, totalPackets);
    }
    
    // 11. 检查当前是否显示连接频率统计列表
    const connectionStatsTab = document.getElementById('connectionStats');
    if (connectionStatsTab && connectionStatsTab.classList.contains('active')) {
        // 重新生成连接频率统计列表
        calculateConnectionStats();
    }
}

// 关闭筛选下拉菜单
function closeFilterDropdown() {
    if (currentFilterDropdown) {
        currentFilterDropdown.remove();
        currentFilterDropdown = null;
        currentFilterColumn = null;
        currentFilterTable = null;
    }
}

// 清除指定表格的所有表头筛选条件
function clearAllTableFilters(tableId) {
    // 检查该表格是否有筛选条件
    if (filters[tableId]) {
        // 获取表格的所有表头
        const table = document.getElementById(tableId);
        if (table) {
            const headers = table.querySelectorAll('th');
            
            // 遍历所有列，清除筛选条件
            headers.forEach((header, columnIndex) => {
                // 跳过操作列
                if (header.textContent.trim() === '操作') return;
                
                // 清除该列的筛选条件
                if (filters[tableId][columnIndex]) {
                    delete filters[tableId][columnIndex];
                    
                    // 更新筛选图标状态和表头样式
                    updateFilterIconState(tableId, columnIndex);
                }
            });
            
            // 如果表格没有筛选条件，删除整个表格的筛选对象
            if (Object.keys(filters[tableId]).length === 0) {
                delete filters[tableId];
            }
            
            // 重新应用所有筛选条件
            applyAllFilters();
        }
    }
}

// 检查值是否符合筛选条件
function isValueFiltered(value, tableId, columnIndex) {
    const tableFilters = filters[tableId] || {};
    const columnFilters = tableFilters[columnIndex] || [];
    
    // 如果没有筛选条件，返回true
    if (columnFilters.length === 0) {
        return true;
    }
    
    // 检查值是否在筛选列表中
    return columnFilters.includes(value);
}

function initTableResizable() {
    // 为所有表格添加拖拽功能
    const tables = document.querySelectorAll('.packets-table');
    tables.forEach(table => {
        const headers = table.querySelectorAll('th');
        headers.forEach(header => {
            // 移除现有的事件监听器，避免重复绑定
            header.removeEventListener('mousedown', handleHeaderMouseDown);
            header.removeEventListener('mousemove', handleHeaderMouseMove);
            
            // 添加拖拽功能，同时保持排序功能
            header.addEventListener('mousedown', handleHeaderMouseDown);
            
            // 在鼠标移动时检测拖拽区域
            header.addEventListener('mousemove', handleHeaderMouseMove);
        });
    });
    
    // 添加全局事件监听器
    document.removeEventListener('mousemove', resizeColumn);
    document.removeEventListener('mouseup', stopResizing);
    document.addEventListener('mousemove', resizeColumn);
    document.addEventListener('mouseup', stopResizing);
}

// 处理表头鼠标按下事件
function handleHeaderMouseDown(e) {
    // 检查是否在拖拽区域
    if (isInResizeZone(e)) {
        e.preventDefault(); // 阻止默认行为，防止触发排序
        startResizing(e);
    }
}

// 处理表头鼠标移动事件
function handleHeaderMouseMove(e) {
    if (isInResizeZone(e)) {
        this.style.cursor = 'col-resize';
    } else {
        this.style.cursor = 'pointer';
    }
}

// 检测是否在拖拽区域
function isInResizeZone(e) {
    const target = e.target;
    const rect = target.getBoundingClientRect();
    const x = e.clientX - rect.left;
    // 扩大拖拽区域到10px
    return x > rect.width - 10;
}

function startResizing(e) {
    isResizing = true;
    currentColumn = e.target;
    currentTable = e.target.closest('.packets-table');
    startX = e.pageX;
    startWidth = e.target.offsetWidth;
    
    // 添加拖拽样式
    document.body.style.cursor = 'col-resize';
    currentColumn.style.cursor = 'col-resize';
    currentColumn.style.userSelect = 'none';
    if (currentTable) {
        currentTable.style.userSelect = 'none';
    }
}

function resizeColumn(e) {
    if (!isResizing || !currentColumn || !currentTable) {
        return;
    }
    
    e.preventDefault(); // 阻止默认行为
    
    const deltaX = e.pageX - startX;
    const newWidth = startWidth + deltaX;
    
    // 确保列宽不小于最小宽度
    if (newWidth > 80) {
        // 设置当前列宽度
        currentColumn.style.width = newWidth + 'px';
        currentColumn.style.minWidth = newWidth + 'px';
        
        // 设置对应列的所有单元格宽度
        const columnIndex = Array.from(currentTable.querySelectorAll('th')).indexOf(currentColumn);
        const rows = currentTable.querySelectorAll('tr');
        rows.forEach(row => {
            const cells = row.querySelectorAll('td, th');
            if (cells[columnIndex]) {
                // 保留原始样式，只更新宽度相关属性
                cells[columnIndex].style.width = newWidth + 'px';
                cells[columnIndex].style.minWidth = newWidth + 'px';
                // 确保文本溢出处理样式被保留
                if (cells[columnIndex].tagName === 'TD') {
                    cells[columnIndex].style.overflow = 'hidden';
                    cells[columnIndex].style.textOverflow = 'ellipsis';
                    cells[columnIndex].style.whiteSpace = 'nowrap';
                }
            }
        });
    }
}

function stopResizing() {
    if (isResizing) {
        isResizing = false;
        
        // 恢复默认样式
        document.body.style.cursor = '';
        if (currentColumn) {
            currentColumn.style.cursor = 'pointer';
            currentColumn.style.userSelect = '';
        }
        if (currentTable) {
            currentTable.style.userSelect = '';
        }
        
        currentColumn = null;
        currentTable = null;
    }
}

function handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    // 更新文件信息
    document.getElementById('fileInfo').textContent = `已选择文件: ${file.name} (${formatFileSize(file.size)})`;
    
    // 显示加载状态
    document.getElementById('loading').style.display = 'block';
    document.getElementById('stats').style.display = 'none';
    
    // 清空之前的结果
    document.getElementById('packetsBody').innerHTML = '<tr><td colspan="8" style="text-align: center; color: #666;">正在分析文件...</td></tr>';
    document.getElementById('packetDetails').innerHTML = '<p style="text-align: center; color: #666;">请进入数据包列表选择要查看的数据包</p>';

    
    // 读取文件
    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const parser = new PcapngParser();
            const result = parser.parseFile(e.target.result);
            
            console.log('解析结果:', result);
            
            originalPackets = result.packets; // 保存原始数据包列表
                currentPackets = [...originalPackets]; // 当前显示的数据包列表
                currentStats = result.stats;
                originalStreams = result.streams; // 保存原始流列表
                currentStreams = result.streams; // 保存当前流信息
                currentTiming = result.timing; // 保存计时数据
                
                // 更新数据包ID缓存，用于快速查找
                updatePacketIdMap();
                
                // 清空响应缓存
                clearResponseCache();
                
                // 清空流的缓存
                Object.values(originalStreams).forEach(stream => {
                    delete stream._cachedPackets;
                    delete stream._cachedProtocolStats;
                    delete stream._cachedProtocolStatsHtml;
                    delete stream._cachedProtocol;
                    delete stream._cachedTotalLength;
                });
                
                // 预计算并缓存常用的统计信息
                precomputeAndCacheStats();
            
            // 更新统计信息
            updateStats(result.stats);
            
            // 更新数据包列表（带分页）
            currentPage = 1; // 重置到第一页
            updateListWithPagination();
            
            // 更新流列表
            updateStreamsList(currentStreams);
            
            // 更新HTTP请求URL列表
            updateAppRequestsList();
            
            // 隐藏加载状态
            document.getElementById('loading').style.display = 'none';
            document.getElementById('stats').style.display = 'block';
        } catch (error) {
            console.error('解析失败:', error);
            console.error('错误堆栈:', error.stack);
            document.getElementById('loading').textContent = '文件解析失败，请检查控制台日志';
            document.getElementById('packetsBody').innerHTML = '<tr><td colspan="8" style="text-align: center; color: #666;">文件解析失败</td></tr>';
            document.getElementById('packetDetails').innerHTML = '<p style="text-align: center; color: #666;">文件解析失败</p>';
        }
    };
    
    reader.onerror = function(e) {
        console.error('文件读取失败:', e);
        document.getElementById('loading').textContent = '文件读取失败，请重试';
    };
    
    reader.readAsArrayBuffer(file);
}

function updateStats(stats) {
    document.getElementById('packetCount').textContent = stats.packetCount;
    document.getElementById('fileSize').textContent = PcapngParser.formatFileSize(stats.fileSize);
    document.getElementById('duration').textContent = stats.duration ? PcapngParser.formatDuration(stats.duration) : 'N/A';
    document.getElementById('avgPacketSize').textContent = stats.avgPacketSize ? stats.avgPacketSize + ' bytes' : '0 bytes';
    
    // 检测并显示设备信息
    const deviceInfo = detectDeviceInfo(originalPackets);
    document.getElementById('deviceInfo').textContent = deviceInfo;
    
    // 计算并显示源地址数量
    const srcAddresses = new Set();
    originalPackets.forEach(packet => {
        if (packet.srcIp) {
            srcAddresses.add(packet.srcIp);
        }
    });
    document.getElementById('srcAddressCount').textContent = srcAddresses.size;
    
    // 计算并显示流量统计
    calculateTrafficStats();
    
    // 计算并显示协议使用统计
    calculateProtocolStats();
    
    // 计算并显示IP+端口连接频率跟踪
    calculateConnectionStats();
    
    // 显示分析时间统计
    displayTimingStats();
}

// 显示分析时间统计
function displayTimingStats() {
    if (!currentTiming) {
        return;
    }
    
    // 阶段名称映射
    const stageNames = {
        fileFormatDetection: '文件格式检测',
        interfaceParsing: '接口信息解析',
        packetParsing: '数据包解析',
        protocolAnalysis: '协议分析',
        streamProcessing: '流处理',
        bleReassembly: 'BLE重组',
        statsCalculation: '统计信息计算',
        tcpReassemblyInfo: 'TCP重组信息生成',
        otherOperations: '其他操作'
    };
    
    // 数据包解析细节阶段名称映射
    const packetParsingDetailsNames = {
        usbPacketParsing: 'USB数据包解析',
        blePacketParsing: 'BLE数据包解析',
        ipv6PacketParsing: 'IPv6数据包解析',
        arpPacketParsing: 'ARP数据包解析',
        ipPacketParsing: 'IPv4数据包解析',
        lldpPacketParsing: 'LLDP数据包解析',
        otherPacketParsing: '其他数据包解析'
    };
    
    // 显示总分析时间
    document.getElementById('totalAnalysisTime').textContent = currentTiming.total.toFixed(2) + ' ms';
    
    // 生成各阶段的时间统计
    const tbody = document.getElementById('timingDetails');
    tbody.innerHTML = '';
    
    // 计算总时间（用于计算占比）
    const totalTime = currentTiming.total;
    
    // 计算已统计的主要阶段时间总和
    let summedTime = 0;
    // 存储主要阶段的时间数据，用于后续计算
    const mainStages = [];
    
    // 遍历所有主要阶段，收集数据
    for (const [stage, time] of Object.entries(currentTiming)) {
        if (stage === 'total' || stage === 'packetParsingDetails') continue;
        summedTime += time;
        mainStages.push({ stage, time });
    }
    
    // 计算未统计的时间（其他时间）
    const otherTime = totalTime - summedTime;
    
    // 遍历所有主要阶段，显示数据
    for (const { stage, time } of mainStages) {
        const percentage = totalTime > 0 ? (time / totalTime * 100).toFixed(2) : '0.00';
        const stageName = stageNames[stage] || stage;
        
        const row = document.createElement('tr');
        row.innerHTML = `
            <td style="padding: 12px; text-align: left; border-bottom: 1px solid #eee; font-weight: bold;">${stageName}</td>
            <td style="padding: 12px; text-align: right; border-bottom: 1px solid #eee; font-weight: bold;">${time.toFixed(2)}</td>
            <td style="padding: 12px; text-align: right; border-bottom: 1px solid #eee; font-weight: bold;">${percentage}%</td>
        `;
        
        tbody.appendChild(row);
        
        // 如果是数据包解析阶段，显示更详细的解析时间
        if (stage === 'packetParsing' && currentTiming.packetParsingDetails) {
            // 遍历数据包解析细节
            for (const [detailStage, detailTime] of Object.entries(currentTiming.packetParsingDetails)) {
                // 对于细分项，占比相对于数据包解析总时间计算
                const packetParsingTime = currentTiming.packetParsing || 1;
                const detailPercentage = (detailTime / packetParsingTime * 100).toFixed(2);
                const detailStageName = packetParsingDetailsNames[detailStage] || detailStage;
                
                const detailRow = document.createElement('tr');
                detailRow.innerHTML = `
                    <td style="padding: 10px 12px 10px 30px; text-align: left; border-bottom: 1px solid #eee; color: #666;">└─ ${detailStageName}</td>
                    <td style="padding: 10px 12px; text-align: right; border-bottom: 1px solid #eee; color: #666;">${detailTime.toFixed(2)}</td>
                    <td style="padding: 10px 12px; text-align: right; border-bottom: 1px solid #eee; color: #666;">${detailPercentage}%</td>
                `;
                
                tbody.appendChild(detailRow);
            }
        }
    }
    
    // 显示未统计的其他时间
    if (otherTime > 0) {
        const percentage = totalTime > 0 ? (otherTime / totalTime * 100).toFixed(2) : '0.00';
        
        const otherRow = document.createElement('tr');
        otherRow.innerHTML = `
            <td style="padding: 12px; text-align: left; border-bottom: 1px solid #eee; font-weight: bold; color: #666;">其他时间</td>
            <td style="padding: 12px; text-align: right; border-bottom: 1px solid #eee; font-weight: bold; color: #666;">${otherTime.toFixed(2)}</td>
            <td style="padding: 12px; text-align: right; border-bottom: 1px solid #eee; font-weight: bold; color: #666;">${percentage}%</td>
        `;
        
        tbody.appendChild(otherRow);
    }
    
    // 显示已统计时间总和，用于验证
    const summedRow = document.createElement('tr');
    summedRow.innerHTML = `
        <td style="padding: 12px; text-align: left; border-bottom: none; font-weight: bold; color: #333; background-color: #f0f8ff;">已统计时间总和</td>
        <td style="padding: 12px; text-align: right; border-bottom: none; font-weight: bold; color: #333; background-color: #f0f8ff;">${summedTime.toFixed(2)}</td>
        <td style="padding: 12px; text-align: right; border-bottom: none; font-weight: bold; color: #333; background-color: #f0f8ff;">${totalTime > 0 ? (summedTime / totalTime * 100).toFixed(2) : '0.00'}%</td>
    `;
    tbody.appendChild(summedRow);
    
    // 显示总时间，用于对比
    const totalRow = document.createElement('tr');
    totalRow.innerHTML = `
        <td style="padding: 12px; text-align: left; border-bottom: none; font-weight: bold; color: #333; background-color: #e8f5e8;">总分析时间</td>
        <td style="padding: 12px; text-align: right; border-bottom: none; font-weight: bold; color: #333; background-color: #e8f5e8;">${totalTime.toFixed(2)}</td>
        <td style="padding: 12px; text-align: right; border-bottom: none; font-weight: bold; color: #333; background-color: #e8f5e8;">100.00%</td>
    `;
    tbody.appendChild(totalRow);
}

// 检测设备信息
function detectDeviceInfo(packets) {
    if (!packets || packets.length === 0) {
        return 'N/A';
    }
    
    // 根据数据包特征检测设备类型
    let deviceType = 'Unknown';
    
    // 检测BLE数据包
    const hasBlePackets = packets.some(packet => 
        packet.protocol && packet.protocol.startsWith('BLE') ||
        packet.protocolChain && packet.protocolChain.includes('BLE') ||
        packet.layers?.link?.type === 'BLE' ||
        [251, 252, 101].includes(packet.linkType)
    );
    if (hasBlePackets) {
        return 'BLE设备';
    }
    
    // 检测USBPcap数据包
    const hasUsbPackets = packets.some(packet => 
        packet.protocol === 'USB' || packet.protocol === 'HCI_USB' ||
        packet.protocolChain && packet.protocolChain.includes('USB') ||
        packet.layers?.link?.type === 'USB' ||
        [189, 180, 220, 224, 242, 152].includes(packet.linkType)
    );
    if (hasUsbPackets) {
        return 'USBPcap';
    }
    
    // 检测VMware虚拟网络数据包
    const hasVmwarePackets = packets.some(packet => {
        // VMware虚拟机的MAC地址通常以00:50:56开头
        const srcMac = packet.layers?.link?.srcMac;
        const dstMac = packet.layers?.link?.dstMac;
        return (srcMac && srcMac.startsWith('00:50:56')) || (dstMac && dstMac.startsWith('00:50:56'));
    });
    if (hasVmwarePackets) {
        return 'VMware虚拟网络';
    }
    
    // 检测VirtualBox虚拟网络数据包
    const hasVirtualBoxPackets = packets.some(packet => {
        // VirtualBox虚拟机的MAC地址通常以08:00:27开头
        const srcMac = packet.layers?.link?.srcMac;
        const dstMac = packet.layers?.link?.dstMac;
        return (srcMac && srcMac.startsWith('08:00:27')) || (dstMac && dstMac.startsWith('08:00:27'));
    });
    if (hasVirtualBoxPackets) {
        return 'VirtualBox虚拟网络';
    }
    
    // 检测Hyper-V虚拟网络数据包
    const hasHyperVPackets = packets.some(packet => {
        // Hyper-V虚拟机的MAC地址通常以00:15:5d开头
        const srcMac = packet.layers?.link?.srcMac;
        const dstMac = packet.layers?.link?.dstMac;
        return (srcMac && srcMac.startsWith('00:15:5d')) || (dstMac && dstMac.startsWith('00:15:5d'));
    });
    if (hasHyperVPackets) {
        return 'Hyper-V虚拟网络';
    }
    
    // 检测标准以太网卡 - 更健壮的检测逻辑
    const hasEthernetPackets = packets.some(packet => {
        return packet.protocol === 'IP' || packet.protocol === 'IPv6' || packet.protocol === 'ARP' ||
               packet.protocolChain && (packet.protocolChain.includes('IP') || packet.protocolChain.includes('ARP')) ||
               packet.layers?.link?.type === 'Ethernet' ||
               packet.layers?.network?.version === 4 ||
               packet.layers?.network?.version === 6 ||
               packet.linkType === 1; // 链路类型1表示以太网
    });
    if (hasEthernetPackets) {
        return '标准以太网卡';
    }
    
    return deviceType;
}

// 判断是否为本地IP地址
function isLocalIp(ip) {
    // 匹配私有IP地址范围：10.x.x.x, 172.16.x.x-172.31.x.x, 192.168.x.x, 127.x.x.x
    const localIpRegex = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/;
    return localIpRegex.test(ip);
}

// 计算流量统计
function calculateTrafficStats() {
    let totalBytes = 0;
    let sendBytes = 0;
    let receiveBytes = 0;
    
    // 计算总流量、发送流量和接收流量
    originalPackets.forEach(packet => {
        totalBytes += packet.packetLen;
        
        // 检测数据包是发送还是接收：源IP是本地IP则为发送，否则为接收
        if (packet.srcIp && isLocalIp(packet.srcIp)) {
            sendBytes += packet.packetLen;
        } else if (packet.dstIp && isLocalIp(packet.dstIp)) {
            receiveBytes += packet.packetLen;
        }
    });
    
    // 确保统计准确
    if (receiveBytes === 0 && totalBytes > 0) {
        // 如果没有检测到本地IP，可能是所有IP都是公共IP或解析失败
        // 尝试另一种方式：计算平均包大小，区分发送和接收
        const packetCount = originalPackets.length;
        if (packetCount > 0) {
            // 简单均分，实际应用中可能需要更智能的方式
            sendBytes = Math.floor(totalBytes / 2);
            receiveBytes = totalBytes - sendBytes;
        }
    }
    
    // 更新流量统计显示
    document.getElementById('totalBytes').textContent = PcapngParser.formatFileSize(totalBytes);
    document.getElementById('sendBytes').textContent = PcapngParser.formatFileSize(sendBytes);
    document.getElementById('receiveBytes').textContent = PcapngParser.formatFileSize(receiveBytes);
    
    // 计算平均速率
    if (currentStats && currentStats.duration) {
        const avgBytesPerSec = totalBytes / currentStats.duration;
        document.getElementById('avgBytesPerSec').textContent = PcapngParser.formatFileSize(avgBytesPerSec) + '/s';
    } else {
        document.getElementById('avgBytesPerSec').textContent = '0 bytes/s';
    }
}

// 计算协议使用统计
function calculateProtocolStats() {
    const protocolCounts = {};
    
    // 统计各协议栈链的使用次数
    originalPackets.forEach(packet => {
        let protocolChainStr;
        
        // 优先使用解析器中已经设置好的协议链
        if (packet.protocolChain && packet.protocolChain.includes(' -> ')) {
            protocolChainStr = packet.protocolChain;
        } else {
            // 构建协议栈链
            const protocolChain = [];
            
            // 检查是否为非IP协议（USB、BLE、HCI_USB等）
            if (packet.protocol === 'ARP') {
                // ARP协议直接显示
                protocolChain.push('ARP');
            } else if (packet.protocol.startsWith('USB') || packet.protocol.startsWith('BLE') || packet.protocol === 'HCI_USB') {
                // USB或BLE相关协议，直接使用其协议类型
                protocolChain.push(packet.protocol);
            } else {
                // IP协议
                const networkProtocol = packet.layers?.network?.version === 6 ? 'IPv6' : 'IP';
                protocolChain.push(networkProtocol);
                
                // 传输层协议
                const transportProtocol = packet.layers?.transport?.type || packet.protocol;
                protocolChain.push(transportProtocol);
                
                // 应用层协议
                if (packet.layers?.application) {
                    // 检查是否有多层应用协议（如TLS over HTTP）
                    let appProtocol = packet.layers.application.protocol;
                    if (appProtocol === 'HTTPS') {
                        // HTTPS协议展开为TCP -> TLS -> HTTP
                        protocolChain.pop(); // 移除TCP
                        protocolChain.push('TCP');
                        protocolChain.push('TLS');
                        protocolChain.push('HTTP');
                    } else {
                    // 只有当应用层协议不是"Unknown"时才添加到协议链中
                    if (appProtocol !== 'Unknown') {
                        protocolChain.push(appProtocol);
                    }
                    }
                }
            }
            
            // 生成协议栈链字符串
            protocolChainStr = protocolChain.join(' -> ');
        }
        
        // 统计协议栈链出现次数
        protocolCounts[protocolChainStr] = (protocolCounts[protocolChainStr] || 0) + 1;
    });
    
    // 生成协议统计的可视化元素
    generateProtocolStats(protocolCounts);
}

// 生成协议统计的可视化元素
function generateProtocolStats(protocolCounts) {
    const container = document.getElementById('appProtocolStats');
    container.innerHTML = '';
    
    // 按使用次数排序，显示所有协议
    const sortedProtocols = Object.entries(protocolCounts)
        .sort(([,a], [,b]) => b - a); // 按使用次数降序排序
    
    // 生成每个协议的统计卡片
    sortedProtocols.forEach(([protocolChain, count]) => {
        const protocolCard = document.createElement('div');
        protocolCard.style.cssText = `
            background-color: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            min-width: 200px;
            max-width: 300px;
            cursor: pointer;
            transition: all 0.2s ease;
        `;
        protocolCard.innerHTML = `
            <div style="font-weight: bold; margin-bottom: 5px; color: #333; font-size: 13px;">${protocolChain}</div>
            <div style="font-size: 24px; font-weight: bold; color: #3498db;">${count}</div>
            <div style="font-size: 12px; color: #666; margin-top: 3px;">数据包</div>
        `;
        
        // 添加点击事件，点击后在数据包列表中显示该协议的数据包
        protocolCard.addEventListener('click', () => {
            // 切换到数据包列表标签
            switchTab('packets');
            
            // 清除现有的筛选条件
            if (filters['packetsTable']) {
                delete filters['packetsTable'];
            }
            
            // 直接过滤数据包，不使用筛选条件系统
            currentPackets = originalPackets.filter(packet => {
                return packet.protocolChain === protocolChain;
            });
            
            // 更新数据包列表（带分页）
            currentPage = 1; // 重置到第一页
            updateListWithPagination();
        });
        
        container.appendChild(protocolCard);
    });
}

// 解析带端口的IP地址（支持IPv4和IPv6）
function parseAddressWithPort(addr) {
    // 检查是否是IPv6地址（包含多个冒号）
    const colonCount = (addr.match(/:/g) || []).length;
    if (colonCount > 1) {
        // IPv6地址，端口在最后一个冒号后面
        const lastColonIndex = addr.lastIndexOf(':');
        const ip = addr.substring(0, lastColonIndex);
        const port = addr.substring(lastColonIndex + 1);
        return [ip, port];
    } else {
        // IPv4地址
        return addr.split(':');
    }
}

// 计算IP端口使用统计
function calculateIpPortStats() {
    const ipPortCounts = {};
    
    // 获取当前过滤后的数据包
    const packetsToUse = currentPackets.length > 0 ? currentPackets : originalPackets;
    
    // 统计每个IP使用的端口及其包数量
    packetsToUse.forEach(packet => {
        // 统计源IP和源端口
        const srcIp = packet.srcIp;
        const srcPort = packet.layers?.transport?.srcPort || '0';
        const srcKey = `${srcIp}:${srcPort}`;
        ipPortCounts[srcKey] = (ipPortCounts[srcKey] || 0) + 1;
        
        // 统计目标IP和目标端口
        const dstIp = packet.dstIp;
        const dstPort = packet.layers?.transport?.dstPort || '0';
        const dstKey = `${dstIp}:${dstPort}`;
        ipPortCounts[dstKey] = (ipPortCounts[dstKey] || 0) + 1;
    });
    
    return ipPortCounts;
}

// 常见端口描述映射表
const commonPortDescriptions = {
    // 基础网络服务
    '20': 'FTP数据传输端口，用于FTP协议的数据传输',
    '21': 'FTP控制端口，用于FTP协议的命令控制',
    '22': 'SSH端口，用于安全的远程登录和文件传输',
    '23': 'Telnet端口，用于远程登录（明文传输，不安全）',
    '25': 'SMTP端口，用于电子邮件发送',
    '53': 'DNS端口，用于域名解析服务',
    '67': 'DHCP服务器端口，用于IP地址分配',
    '68': 'DHCP客户端端口，用于获取IP地址',
    '80': 'HTTP端口，用于超文本传输协议',
    '110': 'POP3端口，用于电子邮件接收',
    '143': 'IMAP端口，用于邮件服务器访问',
    '443': 'HTTPS端口，用于加密的HTTP传输',
    '465': 'SMTPS端口，用于加密的邮件发送',
    '587': 'SMTP提交端口，用于邮件客户端提交邮件',
    '993': 'IMAPS端口，用于加密的IMAP访问',
    '995': 'POP3S端口，用于加密的POP3访问',
    '1433': 'SQL Server端口，用于Microsoft SQL Server数据库',
    '1521': 'Oracle数据库端口，用于Oracle数据库服务',
    '3306': 'MySQL数据库端口，用于MySQL数据库系统默认的TCP/IP连接',
    '3389': 'RDP端口，用于Windows远程桌面协议',
    '5432': 'PostgreSQL端口，用于PostgreSQL数据库',
    '6379': 'Redis端口，用于Redis键值存储数据库',
    '8080': 'HTTP替代端口，常用于Web服务器的替代端口',
    '8443': 'HTTPS替代端口，常用于Web服务器的加密替代端口',
    '9000': 'PHP-FPM端口，用于PHP FastCGI进程管理器',
    '27017': 'MongoDB端口，用于MongoDB NoSQL数据库',
    
    // 扩展端口列表
    '7': 'Echo端口，用于测试网络连接',
    '9': 'Discard端口，用于测试数据丢弃',
    '13': 'Daytime端口，用于获取日期和时间',
    '17': 'Quote of the Day端口，用于获取每日引用',
    '19': 'Character Generator端口，用于生成字符流',
    '37': 'Time端口，用于获取网络时间',
    '42': 'Name Server端口，用于主机名解析',
    '43': 'Whois端口，用于查询域名注册信息',
    '111': 'RPC端口，用于远程过程调用',
    '123': 'NTP端口，用于网络时间协议',
    '135': 'DCE/RPC端口，用于分布式计算环境远程过程调用',
    '137': 'NetBIOS名称服务端口',
    '138': 'NetBIOS数据报服务端口',
    '139': 'NetBIOS会话服务端口，用于Windows文件和打印机共享',
    '161': 'SNMP端口，用于简单网络管理协议',
    '162': 'SNMP陷阱端口，用于SNMP告警',
    '179': 'BGP端口，用于边界网关协议',
    '389': 'LDAP端口，用于轻量级目录访问协议',
    '445': 'SMB端口，用于服务器消息块协议，Windows文件共享',
    '464': 'Kerberos密码更改端口',
    '514': 'Syslog端口，用于系统日志服务',
    '515': 'LPD端口，用于行式打印机后台处理系统',
    '548': 'AFP端口，用于Apple文件协议',
    '636': 'LDAPS端口，用于加密的LDAP访问',
    '989': 'FTPS数据端口，用于加密的FTP数据传输',
    '990': 'FTPS控制端口，用于加密的FTP控制',
    '1025': 'Microsoft RPC端口，用于Windows RPC服务',
    '1194': 'OpenVPN端口，用于虚拟专用网络',
    '1527': 'Derby数据库端口，用于Apache Derby数据库',
    '1723': 'PPTP端口，用于点对点隧道协议',
    '2049': 'NFS端口，用于网络文件系统',
    '2483': 'Oracle Net Listener端口，用于Oracle数据库监听',
    '2484': 'Oracle Net Listener SSL端口，用于加密的Oracle监听',
    '3128': 'Squid代理端口，用于HTTP代理服务',
    '3260': 'iSCSI端口，用于Internet小型计算机系统接口',
    '3366': 'MYSQL Cluster端口，用于MySQL集群服务',
    '4333': 'mSQL端口，用于小型SQL数据库',
    '5000': 'UPnP端口，用于通用即插即用服务',
    '5060': 'SIP端口，用于会话初始协议，VoIP通信',
    '5061': 'SIPS端口，用于加密的SIP通信',
    '5433': 'PostgreSQL备用端口，PostgreSQL数据库备用端口',
    '5900': 'VNC端口，用于虚拟网络计算，远程桌面',
    '5984': 'CouchDB端口，用于Apache CouchDB数据库',
    '6380': 'Redis备用端口，Redis数据库备用端口',
    '7001': 'WebLogic端口，用于Oracle WebLogic服务器',
    '7077': 'Spark端口，用于Apache Spark集群通信',
    '7474': 'Neo4j端口，用于Neo4j图形数据库',
    '7680': 'Bittorrent端口，用于BitTorrent协议',
    '8000': 'HTTP替代端口，常用于Web开发测试',
    '8008': 'HTTP替代端口，常用于Web服务器',
    '8081': 'HTTP替代端口，常用于Web服务器或应用服务器',
    '8089': 'Splunk端口，用于Splunk监控系统',
    '9042': 'Cassandra端口，用于Apache Cassandra数据库',
    '9160': 'Cassandra Thrift端口，用于Cassandra Thrift接口',
    '9200': 'Elasticsearch HTTP端口，用于Elasticsearch搜索服务',
    '9300': 'Elasticsearch传输端口，用于Elasticsearch节点间通信',
    '10000': 'Webmin端口，用于Web-based系统管理工具',
    '27018': 'MongoDB备用端口，MongoDB数据库备用端口',
    '27019': 'MongoDB分片端口，MongoDB分片集群端口',
    '27020': 'MongoDB仲裁端口，MongoDB仲裁服务器端口',
    
    // 游戏相关端口
    '27000': 'Steam端口，用于Steam游戏平台',
    '27015': 'CS:GO端口，用于反恐精英：全球攻势游戏服务器',
    '27031': 'Steam端口，用于Steam游戏平台',
    '27036': 'Steam端口，用于Steam游戏平台',
    '7777': 'Ark: Survival Evolved端口，用于方舟：生存进化游戏服务器',
    '25565': 'Minecraft端口，用于Minecraft游戏服务器',
    
    // 流媒体相关端口
    '1935': 'RTMP端口，用于实时消息传输协议，流媒体直播',
    '554': 'RTSP端口，用于实时流传输协议，流媒体播放',
    '8554': 'RTSP替代端口，用于实时流传输协议',
    '1935': 'SRT端口，用于安全可靠传输协议，流媒体传输',
    
    // 恶意软件和可疑端口
    '4444': '常见的后门端口，被Metasploit等渗透工具和多种恶意软件使用',
    '5555': 'Android调试端口，也常被恶意软件用于远程控制',
    '6666': '常见的非标准端口，常被僵尸网络（如Mirai、QBot）、IRC后门或自定义恶意软件使用',
    '6667': 'IRC协议默认端口，常被僵尸网络用于命令控制',
    '6668': 'IRC协议备用端口，常用于IRC网络通信',
    '6669': 'IRC协议备用端口，常用于IRC网络通信',
    '7777': '常见的远程控制端口，被多种恶意软件和自定义服务使用',
    '8888': '常见的后门端口，被多种恶意软件使用',
    '9999': '常见的后门端口，被远程控制软件和恶意软件使用',
    '10001': '常见的自定义恶意软件端口，被多种后门程序使用',
    '11111': '常见的僵尸网络控制端口，被多种恶意软件使用',
    '12345': '常见的后门端口，被NetBus等远程控制软件使用',
    '13377': '被DarkComet远程控制软件使用的端口',
    '16666': '常见的恶意软件端口，被多种僵尸网络使用',
    '20000': '常见的自定义端口，常被恶意软件用于命令控制',
    '22222': '常见的SSH替代端口，也被恶意软件使用',
    '31337': '被Back Orifice和多种黑客工具使用的端口',
    '44444': '被NanoCore远程控制软件使用的端口',
    '55555': '常见的恶意软件端口，被多种后门程序使用',
    
    // 其他常用非标准端口
    '1080': 'SOCKS代理默认端口，用于代理服务器',
    '2000': '常见的自定义端口，用于各种应用服务',
    '3000': '常用的Web开发端口，用于Node.js、React等开发服务器',
    '5000': '常用的Web服务端口，用于Python Flask、Django等框架',
    '5001': '常用的HTTPS开发端口，用于加密Web服务',
    '8001': 'HTTP替代端口，常用于Web服务器',
    '8880': '常见的Web服务器替代端口',
    '9001': 'PHP-FPM备用端口，用于PHP FastCGI进程管理器',
    '9090': '常见的监控服务端口，如Prometheus、Grafana等',
    '9100': '常见的打印服务器端口，用于网络打印机',
    '10001': '常见的自定义服务端口',
    '10002': '常见的自定义服务端口',
    '10003': '常见的自定义服务端口'
};

// 检测IP是否为内网IP
function isPrivateIp(ip) {
    const parts = ip.split('.').map(Number);
    return (
        // 10.0.0.0/8
        parts[0] === 10 ||
        // 172.16.0.0/12
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
        // 192.168.0.0/16
        (parts[0] === 192 && parts[1] === 168) ||
        // 127.0.0.0/8 (localhost)
        parts[0] === 127
    );
}

// 获取IP归属地（简化版，实际应用中可接入IP库API）
function getIpLocation(ip) {
    // 特殊IP地址处理
    const specialIps = {
        '0.0.0.0': '无效地址/任意地址',
        '127.0.0.1': '环回地址',
        '255.255.255.255': '广播地址'
    };
    
    // 检查特殊IP地址
    if (specialIps[ip]) {
        return specialIps[ip];
    }
    
    // 检查链路本地地址（169.254.0.0/16）
    const ipParts = ip.split('.').map(Number);
    if (ipParts[0] === 169 && ipParts[1] === 254) {
        return '链路本地地址';
    }
    
    // 检查是否为内网IP
    if (isPrivateIp(ip)) {
        return '内网';
    }
    
    // 其他为外网IP
    return '外网';
}

// 获取端口描述
function getPortDescription(port) {
    return commonPortDescriptions[port] || '';
}

// 生成IP端口统计表
function generateIpPortStatsTable(ipPortCounts, ipColors) {
    const container = document.getElementById('ipPortStatsContent');
    container.innerHTML = '';
    
    // 创建表格标题
    const tableTitle = document.createElement('h4');
    tableTitle.textContent = 'IP端口使用统计表';
    tableTitle.style.cssText = `
        margin-bottom: 15px;
        color: #555;
        font-size: 16px;
        font-weight: 600;
    `;
    container.appendChild(tableTitle);
    
    // 统计每个IP开放的所有端口
    const ipPortsMap = {};
    Object.keys(ipPortCounts).forEach(ipPort => {
        const [ip, port] = parseAddressWithPort(ipPort);
        if (!ipPortsMap[ip]) {
            ipPortsMap[ip] = new Set();
        }
        ipPortsMap[ip].add(port);
    });
    
    // 创建每个IP开放端口的显示区域
    const ipPortsSection = document.createElement('div');
    ipPortsSection.style.cssText = `
        margin-bottom: 20px;
        padding: 15px;
        background-color: #f8f9fa;
        border-radius: 8px;
        border: 1px solid #e9ecef;
    `;
    
    const ipPortsTitle = document.createElement('h5');
    ipPortsTitle.textContent = '每个IP开放的端口号';
    ipPortsTitle.style.cssText = `
        margin-bottom: 10px;
        color: #495057;
        font-size: 14px;
        font-weight: 600;
    `;
    ipPortsSection.appendChild(ipPortsTitle);
    
    // 生成美观紧凑的IP端口卡片网格
    const ipPortsGrid = document.createElement('div');
    
    // 清除筛选按钮添加到容器中，位于IP端口统计区域的下方
    const clearFilterBtn = document.createElement('button');
    clearFilterBtn.textContent = '清除筛选';
    clearFilterBtn.style.cssText = `
        margin: 10px 0;
        padding: 6px 12px;
        background-color: #dc3545;
        color: white;
        border: none;
        border-radius: 4px;
        font-size: 12px;
        cursor: pointer;
        transition: background-color 0.2s ease;
        float: right;
    `;
    clearFilterBtn.addEventListener('mouseover', () => {
        clearFilterBtn.style.backgroundColor = '#c82333';
    });
    clearFilterBtn.addEventListener('mouseout', () => {
        clearFilterBtn.style.backgroundColor = '#dc3545';
    });
    clearFilterBtn.addEventListener('click', () => {
        clearAllFilters();
    });
    ipPortsGrid.style.cssText = `
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
        gap: 10px;
        max-height: 200px;
        overflow-y: auto;
        padding-right: 5px;
    `;
    
    // 自定义滚动条样式
    ipPortsGrid.style.scrollbarWidth = 'thin';
    ipPortsGrid.style.scrollbarColor = '#c1c1c1 #f1f1f1';
    
    Object.entries(ipPortsMap).forEach(([ip, ports]) => {
        // 当IP为N/A时不显示卡片
        if (ip === 'N/A') {
            return;
        }
        const ipCard = document.createElement('div');
        ipCard.style.cssText = `
            background-color: white;
            padding: 10px;
            border-radius: 6px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            transition: transform 0.1s ease, box-shadow 0.1s ease;
            border: 1px solid #e9ecef;
        `;
        
        // 鼠标悬停效果
        ipCard.addEventListener('mouseenter', () => {
            ipCard.style.transform = 'translateY(-2px)';
            ipCard.style.boxShadow = '0 3px 6px rgba(0, 0, 0, 0.15)';
        });
        
        ipCard.addEventListener('mouseleave', () => {
            ipCard.style.transform = 'translateY(0)';
            ipCard.style.boxShadow = '0 1px 3px rgba(0, 0, 0, 0.1)';
        });
        
        // IP地址和端口总数
        const ipHeader = document.createElement('div');
        ipHeader.style.cssText = `
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
        `;
        
        const ipLabel = document.createElement('div');
        ipLabel.style.cssText = `
            font-weight: bold;
            font-size: 11px;
            color: ${ipColors[ip] || '#3498db'};
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        `;
        ipLabel.textContent = ip;
        
        const portCountBadge = document.createElement('span');
        portCountBadge.style.cssText = `
            background-color: #28a745;
            color: white;
            padding: 2px 6px;
            border-radius: 10px;
            font-size: 10px;
            font-weight: bold;
        `;
        portCountBadge.textContent = ports.size;
        
        ipHeader.appendChild(ipLabel);
        ipHeader.appendChild(portCountBadge);
        ipCard.appendChild(ipHeader);
        
        // 端口列表 - 紧凑美观格式
        const portsList = document.createElement('div');
        portsList.style.cssText = `
            background-color: #f8f9fa;
            padding: 6px 8px;
            border-radius: 4px;
            font-size: 10px;
            color: #495057;
            max-height: 80px;
            overflow-y: auto;
            line-height: 1.4;
        `;
        
        // 将端口转换为数组并排序
        const sortedPorts = Array.from(ports).sort((a, b) => parseInt(a) - parseInt(b));
        
        // 显示前5个端口，后面的用省略号
        let displayPorts = sortedPorts;
        let hasMore = false;
        if (sortedPorts.length > 5) {
            displayPorts = sortedPorts.slice(0, 5);
            hasMore = true;
        }
        
        portsList.innerHTML = displayPorts.join(', ') + (hasMore ? `, ... (+${sortedPorts.length - 5})` : '');
        
        // 添加端口列表悬停效果：显示所有端口
        portsList.addEventListener('mouseenter', () => {
            if (hasMore) {
                portsList.innerHTML = sortedPorts.join(', ');
                portsList.style.maxHeight = '150px';
                portsList.style.overflowY = 'auto';
            }
        });
        
        portsList.addEventListener('mouseleave', () => {
            if (hasMore) {
                portsList.innerHTML = displayPorts.join(', ') + `, ... (+${sortedPorts.length - 5})`;
                portsList.style.maxHeight = '80px';
            }
        });
        
        ipCard.appendChild(portsList);
        ipPortsGrid.appendChild(ipCard);
    });
    
    ipPortsSection.appendChild(ipPortsGrid);
    container.appendChild(ipPortsSection);
    
    // 将清除筛选按钮添加到IP端口统计区域的下方
    container.appendChild(clearFilterBtn);
    
    // 创建一个清除浮动的元素，确保布局正常
    const clearFloat = document.createElement('div');
    clearFloat.style.cssText = 'clear: both;';
    container.appendChild(clearFloat);
    
    // 创建表格
    const table = document.createElement('table');
    table.id = 'ipPortStatsTable';
    table.style.cssText = `
        width: 100%;
        border-collapse: collapse;
        background-color: white;
        border-radius: 8px;
        overflow: hidden;
    `;
    
    // 创建表头
    const thead = table.createTHead();
    const headerRow = thead.insertRow();
    const headers = [
        { text: 'IP地址', field: 'ip' },
        { text: '归属地', field: 'location' },
        { text: '端口', field: 'port' },
        { text: '端口描述', field: 'portDesc' },
        { text: '数据包数量', field: 'count' },
        { text: '占比', field: 'percentage' }
    ];
    headers.forEach((header, index) => {
        const th = headerRow.insertCell();
        th.innerHTML = `${header.text}<span class="filter-icon" data-column="${index}" data-table-id="ipPortStatsTable">▼</span>`;
        th.style.cssText = `
            padding: 12px;
            text-align: left;
            border-bottom: 2px solid #ddd;
            background-color: #f2f2f2;
            font-weight: 600;
            color: #333;
            cursor: pointer;
            position: relative;
        `;
        // 添加点击排序事件
        th.addEventListener('click', function(e) {
            if (!e.target.classList.contains('filter-icon')) {
                sortIpPortStats(header.field);
            }
        });
        // 添加筛选图标点击事件
        const filterIcon = th.querySelector('.filter-icon');
        filterIcon.addEventListener('click', function(e) {
            e.stopPropagation();
            toggleFilterDropdown(e, th, index, table);
        });
    });
    
    // 创建表格主体
    const tbody = table.createTBody();
    
    // 计算IP端口统计的总计数
    const totalIpPortCounts = Object.values(ipPortCounts).reduce((sum, count) => sum + count, 0);
    
    // 转换为包含完整信息的数组，便于排序
    const ipPortArray = Object.entries(ipPortCounts).map(([ipPort, count]) => {
        const [ip, port] = parseAddressWithPort(ipPort);
        const location = getIpLocation(ip);
        const portDesc = getPortDescription(port);
        const percentage = totalIpPortCounts > 0 ? ((count / totalIpPortCounts) * 100).toFixed(2) : '0.00';
        
        return {
            ip,
            port,
            count,
            location,
            portDesc,
            percentage: parseFloat(percentage),
            ipPort
        };
    });
    
    // 应用筛选条件
    let filteredIpPortArray = [...ipPortArray];
    const tableFilters = filters['ipPortStatsTable'] || {};
    
    // 遍历所有筛选条件，应用到数据上
    Object.entries(tableFilters).forEach(([columnIndexStr, filterValues]) => {
        const columnIndex = parseInt(columnIndexStr);
        filteredIpPortArray = filteredIpPortArray.filter(item => {
            let cellValue;
            switch(columnIndex) {
                case 0: cellValue = item.ip; break;
                case 1: cellValue = item.location; break;
                case 2: cellValue = item.port; break;
                case 3: cellValue = item.portDesc; break;
                case 4: cellValue = item.count.toString(); break;
                case 5: cellValue = item.percentage.toFixed(2) + '%'; break;
                default: cellValue = '';
            }
            return filterValues.includes(cellValue);
        });
    });
    
    // 根据当前排序字段和方向排序
    const sortedIpPortArray = [...filteredIpPortArray].sort((a, b) => {
        let aValue, bValue;
        
        // 根据字段获取值
        switch (currentIpPortSortField) {
            case 'ip':
                aValue = a.ip;
                bValue = b.ip;
                break;
            case 'location':
                aValue = a.location;
                bValue = b.location;
                break;
            case 'port':
                aValue = parseInt(a.port);
                bValue = parseInt(b.port);
                break;
            case 'portDesc':
                aValue = a.portDesc;
                bValue = b.portDesc;
                break;
            case 'count':
                aValue = a.count;
                bValue = b.count;
                break;
            case 'percentage':
                aValue = a.percentage;
                bValue = b.percentage;
                break;
            default:
                aValue = a.count;
                bValue = b.count;
        }
        
        // 根据值类型进行比较
        let comparison;
        if (typeof aValue === 'number' && typeof bValue === 'number') {
            comparison = aValue - bValue;
        } else {
            comparison = String(aValue).localeCompare(String(bValue));
        }
        
        // 根据排序方向调整结果
        return currentIpPortSortDirection === 'asc' ? comparison : -comparison;
    });
    
    // 生成表格行
    sortedIpPortArray.forEach((item) => {
        const { ip, port, count, location, portDesc, percentage } = item;
        const row = tbody.insertRow();
        
        // IP地址列
        const ipCell = row.insertCell();
        ipCell.innerHTML = `<span style="color: ${ipColors[ip] || '#3498db'}">${ip}</span>`;
        ipCell.style.cssText = `
            padding: 10px 12px;
            border-bottom: 1px solid #eee;
            white-space: nowrap;
            font-family: Arial, sans-serif;
        `;
        
        // 归属地列
        const locationCell = row.insertCell();
        const ipLocation = getIpLocation(ip);
        locationCell.textContent = ipLocation;
        locationCell.style.cssText = `
            padding: 10px 12px;
            border-bottom: 1px solid #eee;
            white-space: nowrap;
            font-family: Arial, sans-serif;
        `;
        
        // 端口列
        const portCell = row.insertCell();
        portCell.textContent = port;
        portCell.style.cssText = `
            padding: 10px 12px;
            border-bottom: 1px solid #eee;
            text-align: center;
            font-family: Arial, sans-serif;
        `;
        
        // 端口描述列
        const portDescCell = row.insertCell();
        portDescCell.textContent = portDesc;
        portDescCell.style.cssText = `
            padding: 10px 12px;
            border-bottom: 1px solid #eee;
            font-family: Arial, sans-serif;
        `;
        
        // 包数量列
        const countCell = row.insertCell();
        countCell.textContent = count;
        countCell.style.cssText = `
            padding: 10px 12px;
            border-bottom: 1px solid #eee;
            text-align: center;
            font-weight: bold;
            color: #2ecc71;
            font-family: Arial, sans-serif;
        `;
        
        // 占比列
        const percentageCell = row.insertCell();
        percentageCell.textContent = `${percentage.toFixed(2)}%`;
        percentageCell.style.cssText = `
            padding: 10px 12px;
            border-bottom: 1px solid #eee;
            text-align: center;
            color: #666;
            font-family: Arial, sans-serif;
        `;
        
        // 添加点击事件，点击后在数据包列表中显示该IP端口的数据包
        row.style.cursor = 'pointer';
        row.style.transition = 'background-color 0.2s ease';
        row.addEventListener('mouseenter', () => {
            row.style.backgroundColor = '#f5f5f5';
        });
        row.addEventListener('mouseleave', () => {
            row.style.backgroundColor = 'white';
        });
        row.addEventListener('click', () => {
            // 切换到数据包列表标签
            switchTab('packets');
            
            // 清除现有的筛选条件
            if (filters['packetsTable']) {
                delete filters['packetsTable'];
            }
            
            // 过滤数据包，匹配源IP+端口或目标IP+端口
            currentPackets = originalPackets.filter(packet => {
                // 检查源IP和源端口
                const packetSrcIp = packet.srcIp;
                const packetSrcPort = (packet.layers?.transport?.srcPort || '').toString();
                
                // 检查目标IP和目标端口
                const packetDstIp = packet.dstIp;
                const packetDstPort = (packet.layers?.transport?.dstPort || '').toString();
                
                // 处理端口为0的特殊情况
                const isSrcMatch = packetSrcIp === ip && 
                    (port === '0' ? (packetSrcPort === '' || packetSrcPort === '0') : packetSrcPort === port);
                
                const isDstMatch = packetDstIp === ip && 
                    (port === '0' ? (packetDstPort === '' || packetDstPort === '0') : packetDstPort === port);
                
                // 匹配源IP+端口或目标IP+端口的数据包
                return isSrcMatch || isDstMatch;
            });
            
            // 更新数据包列表（带分页）
            currentPage = 1; // 重置到第一页
            updateListWithPagination();
        });
    });
    
    // 添加表格到容器
    container.appendChild(table);
    
    // 显示内容，隐藏加载提示
    container.style.display = 'block';
    document.getElementById('ipPortStatsLoading').style.display = 'none';
    
    // 确保分页控件隐藏
    const pagination = document.getElementById('pagination');
    if (pagination) {
        pagination.style.display = 'none';
    }
}

// 计算IP+端口连接频率跟踪
function calculateConnectionStats() {
    const connectionCounts = {};
    
    // 统计各IP+端口连接的使用次数
    originalPackets.forEach(packet => {
        const srcIp = packet.srcIp;
        const srcPort = packet.layers?.transport?.srcPort || 0;
        const dstIp = packet.dstIp;
        const dstPort = packet.layers?.transport?.dstPort || 0;
        
        // 生成连接标识
        const connectionKey = `${srcIp}:${srcPort} → ${dstIp}:${dstPort}`;
        connectionCounts[connectionKey] = (connectionCounts[connectionKey] || 0) + 1;
    });
    
    // 生成连接频率跟踪的可视化元素
    generateConnectionStats(connectionCounts);
}

// 生成唯一颜色的函数
function generateUniqueColor(ip) {
    // 使用IP地址生成哈希值
    let hash = 0;
    for (let i = 0; i < ip.length; i++) {
        hash = ip.charCodeAt(i) + ((hash << 5) - hash);
    }
    
    // 生成RGB颜色
    const c = (hash & 0x00FFFFFF)
        .toString(16)
        .toUpperCase();
    
    // 确保颜色有6位数字
    const color = '#' + '00000'.substring(0, 6 - c.length) + c;
    
    // 确保颜色有足够的对比度，不要太亮
    const brightness = parseInt(color.slice(1), 16);
    if (brightness > 0xCCCCCC) {
        // 如果颜色太亮，生成一个更深的颜色
        const darkHash = hash - 0x888888;
        const darkColor = (darkHash & 0x00FFFFFF)
            .toString(16)
            .toUpperCase();
        return '#' + '00000'.substring(0, 6 - darkColor.length) + darkColor;
    }
    
    return color;
}

// 计算连接频率统计
function calculateConnectionCounts() {
    const connectionCounts = {};
    
    // 遍历所有数据包，计算每个连接的数据包数量
    currentPackets.forEach(packet => {
        const src = `${packet.srcIp}:${packet.layers?.transport?.srcPort || 0}`;
        const dst = `${packet.dstIp}:${packet.layers?.transport?.dstPort || 0}`;
        const connection = `${src} → ${dst}`;
        
        // 更新连接计数
        if (!connectionCounts[connection]) {
            connectionCounts[connection] = 0;
        }
        connectionCounts[connection]++;
    });
    
    return connectionCounts;
}

// 生成连接频率跟踪的可视化元素
function generateConnectionStats(connectionCounts) {
    // 收集所有IP地址并为每个IP分配唯一颜色
    const ipColors = {};
    Object.keys(connectionCounts).forEach(connection => {
        const [src, dst] = connection.split(' → ');
        const [srcIp] = src.split(':');
        const [dstIp] = dst.split(':');
        
        if (!ipColors[srcIp]) {
            ipColors[srcIp] = generateUniqueColor(srcIp);
        }
        if (!ipColors[dstIp]) {
            ipColors[dstIp] = generateUniqueColor(dstIp);
        }
    });
    
    // 计算IP端口使用统计
    const ipPortCounts = calculateIpPortStats();
    
    // 生成IP端口统计表
    generateIpPortStatsTable(ipPortCounts, ipColors);
    
    // 按连接次数排序
    const sortedConnections = Object.entries(connectionCounts)
        .sort(([,a], [,b]) => b - a); // 显示所有连接
    
    // 计算总数据包数量
    const totalPackets = Object.values(connectionCounts).reduce((sum, count) => sum + count, 0);
    
    // 生成IP+端口连接频率跟踪表
    generateConnectionStatsTable(sortedConnections, ipColors, totalPackets);
}

// 生成IP+端口连接频率跟踪表
function generateConnectionStatsTable(connections, ipColors, totalPackets) {
    const container = document.getElementById('connectionStatsContent');
    container.innerHTML = '';
    
    // 创建表格标题
    const tableTitle = document.createElement('h4');
    tableTitle.textContent = 'IP+端口连接频率统计';
    tableTitle.style.cssText = `
        margin-bottom: 15px;
        color: #555;
        font-size: 16px;
        font-weight: 600;
    `;
    container.appendChild(tableTitle);
    
    // 创建表格
    const table = document.createElement('table');
    table.style.cssText = `
        width: 100%;
        border-collapse: collapse;
        background-color: white;
        border-radius: 8px;
        overflow: hidden;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    `;
    
    // 创建表头
    const thead = table.createTHead();
    const headerRow = thead.insertRow();
    const headers = ['连接', '数据包数量', '占比'];
    headers.forEach(headerText => {
        const th = headerRow.insertCell();
        th.textContent = headerText;
        th.style.cssText = `
            padding: 12px;
            text-align: left;
            border-bottom: 2px solid #ddd;
            background-color: #f2f2f2;
            font-weight: 600;
            color: #333;
        `;
    });
    
    // 创建表格主体
    const tbody = table.createTBody();
    
    connections.forEach(([connection, count]) => {
        const row = tbody.insertRow();
        
        // 解析连接信息
        const [src, dst] = connection.split(' → ');
        
        // 处理IPv6地址和端口的解析
        function parseAddressWithPort(addr) {
            // 检查是否是IPv6地址（包含多个冒号）
            const colonCount = (addr.match(/:/g) || []).length;
            if (colonCount > 1) {
                // IPv6地址，端口在最后一个冒号后面
                const lastColonIndex = addr.lastIndexOf(':');
                const ip = addr.substring(0, lastColonIndex);
                const port = addr.substring(lastColonIndex + 1);
                return [ip, port];
            } else {
                // IPv4地址
                return addr.split(':');
            }
        }
        
        const [srcIp, srcPort] = parseAddressWithPort(src);
        const [dstIp, dstPort] = parseAddressWithPort(dst);
        
        // 生成带有颜色的连接文本
        const coloredConnection = `
            <span style="color: ${ipColors[srcIp]};">${srcIp}:${srcPort}</span> → 
            <span style="color: ${ipColors[dstIp]};">${dstIp}:${dstPort}</span>
        `;
        
        // 计算占比
        const percentage = totalPackets > 0 ? ((count / totalPackets) * 100).toFixed(2) : '0.00';
        
        // 创建表格单元格
        const connectionCell = row.insertCell(0);
        connectionCell.innerHTML = coloredConnection;
        connectionCell.style.cssText = `
            padding: 10px 12px;
            border-bottom: 1px solid #eee;
            white-space: nowrap;
            font-family: Arial, sans-serif;
        `;
        
        const countCell = row.insertCell(1);
        countCell.textContent = count;
        countCell.style.cssText = `
            padding: 10px 12px;
            border-bottom: 1px solid #eee;
            text-align: center;
            font-weight: bold;
            color: #2ecc71;
            font-family: Arial, sans-serif;
        `;
        
        const percentageCell = row.insertCell(2);
        percentageCell.textContent = `${percentage}%`;
        percentageCell.style.cssText = `
            padding: 10px 12px;
            border-bottom: 1px solid #eee;
            text-align: center;
            color: #666;
            font-family: Arial, sans-serif;
        `;
        
        // 添加点击事件，点击后在数据包列表中显示该连接的数据包
        row.style.cursor = 'pointer';
        row.style.transition = 'background-color 0.2s ease';
        row.addEventListener('mouseenter', () => {
            row.style.backgroundColor = '#f5f5f5';
        });
        row.addEventListener('mouseleave', () => {
            row.style.backgroundColor = 'white';
        });
        row.addEventListener('click', () => {
            // 切换到数据包列表标签
            switchTab('packets');
            
            // 清除现有的筛选条件
            if (filters['packetsTable']) {
                delete filters['packetsTable'];
            }
            
            // 过滤数据包，只匹配所选方向的连接
            currentPackets = originalPackets.filter(packet => {
                // 检查源IP和源端口
                const packetSrcIp = packet.srcIp;
                const packetSrcPort = (packet.layers?.transport?.srcPort || '').toString();
                
                // 检查目标IP和目标端口
                const packetDstIp = packet.dstIp;
                const packetDstPort = (packet.layers?.transport?.dstPort || '').toString();
                
                // 处理端口为0的特殊情况：当连接显示端口为0时，匹配实际数据包中无端口或端口为0的情况
                const isSrcPortMatch = srcPort === '0' ? 
                    (packetSrcPort === '' || packetSrcPort === '0') : 
                    packetSrcPort === srcPort;
                
                const isDstPortMatch = dstPort === '0' ? 
                    (packetDstPort === '' || packetDstPort === '0') : 
                    packetDstPort === dstPort;
                
                // 只匹配所选方向的数据包：源IP:端口 → 目标IP:端口
                return packetSrcIp === srcIp && isSrcPortMatch && packetDstIp === dstIp && isDstPortMatch;
            });
            
            // 更新数据包列表（带分页）
            currentPage = 1; // 重置到第一页
            updateListWithPagination();
        });
    });
    
    // 添加表格到容器
    container.appendChild(table);
    
    // 显示内容，隐藏加载提示
    container.style.display = 'block';
    document.getElementById('connectionStatsLoading').style.display = 'none';
    
    // 确保分页控件隐藏
    const pagination = document.getElementById('pagination');
    if (pagination) {
        pagination.style.display = 'none';
    }
}

// 生成IP+端口连接频率跟踪图
function generateConnectionStatsChart(connections) {
    const container = document.getElementById('connectionStatsChart');
    container.innerHTML = '';
    
    // 创建Canvas元素
    const canvas = document.createElement('canvas');
    canvas.width = container.clientWidth;
    canvas.height = container.clientHeight;
    container.appendChild(canvas);
    
    const ctx = canvas.getContext('2d');
    
    // 设置图表参数
    const margin = { top: 20, right: 20, bottom: 100, left: 60 };
    const chartWidth = canvas.width - margin.left - margin.right;
    const chartHeight = canvas.height - margin.top - margin.bottom;
    
    // 如果没有数据，显示提示
    if (connections.length === 0) {
        ctx.fillStyle = '#666';
        ctx.font = '16px Arial';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('没有连接数据', canvas.width / 2, canvas.height / 2);
        return;
    }
    
    // 限制显示的连接数量，避免图表过于拥挤
    const maxDisplayConnections = Math.min(15, connections.length);
    const displayConnections = connections.slice(0, maxDisplayConnections);
    
    // 计算最大值
    const maxCount = Math.max(...displayConnections.map(([, count]) => count));
    
    // 设置柱状图参数
    const barWidth = chartWidth / displayConnections.length * 0.8;
    const barGap = chartWidth / displayConnections.length * 0.2;
    
    // 绘制坐标轴
    ctx.beginPath();
    ctx.moveTo(margin.left, margin.top);
    ctx.lineTo(margin.left, canvas.height - margin.bottom);
    ctx.lineTo(canvas.width - margin.right, canvas.height - margin.bottom);
    ctx.strokeStyle = '#333';
    ctx.lineWidth = 2;
    ctx.stroke();
    
    // 绘制柱状图
    displayConnections.forEach(([connection, count], index) => {
        // 计算柱状图位置和高度
        const x = margin.left + index * (barWidth + barGap) + barGap / 2;
        const barHeight = (count / maxCount) * chartHeight;
        const y = margin.top + chartHeight - barHeight;
        
        // 生成颜色
        const hue = (index / displayConnections.length) * 360;
        const color = `hsl(${hue}, 70%, 50%)`;
        
        // 绘制柱状图
        ctx.fillStyle = color;
        ctx.fillRect(x, y, barWidth, barHeight);
        
        // 绘制数值
        ctx.fillStyle = '#333';
        ctx.font = '12px Arial';
        ctx.textAlign = 'center';
        ctx.fillText(count, x + barWidth / 2, y - 5);
        
        // 绘制连接标签（旋转45度）
        ctx.save();
        ctx.translate(x + barWidth / 2, canvas.height - margin.bottom + 20);
        ctx.rotate(-Math.PI / 4);
        ctx.fillStyle = '#666';
        ctx.font = '11px Arial';
        ctx.textAlign = 'center';
        
        // 截断过长的连接标签
        const truncatedConnection = connection.length > 20 ? connection.substring(0, 20) + '...' : connection;
        ctx.fillText(truncatedConnection, 0, 0);
        ctx.restore();
    });
    
    // 绘制Y轴刻度
    const yTickCount = 5;
    for (let i = 0; i <= yTickCount; i++) {
        const y = margin.top + (chartHeight / yTickCount) * i;
        const value = Math.round(maxCount - (maxCount / yTickCount) * i);
        
        // 绘制刻度线
        ctx.beginPath();
        ctx.moveTo(margin.left - 5, y);
        ctx.lineTo(margin.left, y);
        ctx.strokeStyle = '#666';
        ctx.lineWidth = 1;
        ctx.stroke();
        
        // 绘制刻度值
        ctx.fillStyle = '#666';
        ctx.font = '11px Arial';
        ctx.textAlign = 'right';
        ctx.fillText(value, margin.left - 10, y + 4);
    }
    
    // 绘制图表标题
    ctx.fillStyle = '#333';
    ctx.font = '14px Arial bold';
    ctx.textAlign = 'center';
    ctx.fillText('IP+端口连接频率分布', canvas.width / 2, margin.top - 5);
}

// 获取数据包功能介绍
function getPacketFunctionDescription(packet) {
    // 获取应用层协议和传输层端口
    const appProtocol = packet.layers?.application?.protocol || 'Unknown';
    const srcPort = packet.layers?.transport?.srcPort;
    const dstPort = packet.layers?.transport?.dstPort;
    const protocol = packet.protocol;
    const info = packet.info.toLowerCase();
    
    // 基于协议和端口识别功能
    let description = '';
    
    // USB相关协议 - 提供具体的功能介绍
    if (protocol === 'USB' || protocol === 'USB_CONTROL' || protocol === 'HCI_USB') {
        // 键盘事件处理 - 优先匹配键盘事件，无论协议类型
        if (info.includes('keyboard:')) {
            const keyMatch = packet.info.match(/\[Keyboard: (.*)\]/);
            if (keyMatch && keyMatch[1]) {
                if (keyMatch[1] === 'Key Released') {
                    return '用户刚刚释放了一个键';
                } else {
                    return `用户在键盘上按下了${keyMatch[1]}键`;
                }
            }
        }
        
        // USB_CONTROL GET DESCRIPTOR 请求
        else if (protocol === 'USB_CONTROL' && info.includes('get descriptor')) {
            if (info.includes('request')) {
                return '主机向USB设备请求描述符信息';
            } else if (info.includes('response')) {
                return 'USB设备向主机返回描述符信息';
            }
        }
        
        // HCI_USB 事件处理
        else if (protocol === 'HCI_USB') {
            if (info.includes('hci_event')) {
                if (info.includes('connection_complete')) {
                    return '蓝牙设备已成功建立连接';
                } else if (info.includes('disconnection_complete')) {
                    return '蓝牙设备已断开连接';
                } else if (info.includes('inquiry_complete')) {
                    return '蓝牙设备查询已完成';
                } else if (info.includes('authentication_complete')) {
                    return '蓝牙设备身份验证已完成';
                } else {
                    return '蓝牙设备向主机发送了事件通知';
                }
            } else if (info.includes('hci_command')) {
                return '主机向蓝牙设备发送了控制命令';
            } else if (info.includes('hci_acldata')) {
                // 更通俗易懂的HCI_ACLDATA描述
                return '蓝牙设备传输数据';
            }
        }
        
        // 通用USB传输
        else if (info.includes('interrupt in')) {
            return 'USB设备向主机发送中断数据';
        } else if (info.includes('interrupt out')) {
            return '主机向USB设备发送中断数据';
        } else if (info.includes('bulk in')) {
            return 'USB设备向主机发送批量数据';
        } else if (info.includes('bulk out')) {
            return '主机向USB设备发送批量数据';
        } else if (info.includes('control')) {
            return '主机与USB设备之间的控制传输';
        }
        
        // 使用默认中文描述
        if (packet.cnDescription) {
            return packet.cnDescription;
        }
    }
    
    // HTTP相关
    if (appProtocol === 'HTTP') {
        if (info.includes('get')) {
            description = 'HTTP GET请求 - 浏览网页时从服务器获取内容（如图片、文字）的协议';
        } else if (info.includes('post')) {
            description = 'HTTP POST请求 - 向服务器提交数据（如登录、上传文件）的协议';
        } else if (info.includes('put')) {
            description = 'HTTP PUT请求 - 更新服务器上文件或数据的协议';
        } else if (info.includes('delete')) {
            description = 'HTTP DELETE请求 - 删除服务器上内容的协议';
        } else if (info.includes('response')) {
            description = 'HTTP响应 - 服务器对请求的回应（如返回网页内容）';
        } else {
            description = 'HTTP请求/响应 - 互联网上最常用的网页访问协议';
        }
    }
    
    // HTTPS相关
    else if (appProtocol === 'HTTPS') {
        description = 'HTTPS加密通信 - 加密版的HTTP协议，保护数据传输安全（如网上银行、购物）';
    }
    
    // FTP相关
    else if (appProtocol === 'FTP' || srcPort === 20 || srcPort === 21 || dstPort === 20 || dstPort === 21) {
        if (info.includes('auth') || info.includes('user') || info.includes('pass')) {
            description = 'FTP认证 - 登录文件服务器的验证过程';
        } else if (info.includes('list') || info.includes('ls')) {
            description = 'FTP列表请求 - 查看文件服务器上的文件和文件夹';
        } else if (info.includes('retr')) {
            description = 'FTP文件下载 - 从文件服务器获取文件';
        } else if (info.includes('stor')) {
            description = 'FTP文件上传 - 向文件服务器发送文件';
        } else {
            description = 'FTP控制连接 - 管理文件传输过程的协议';
        }
    }
    
    // SMTP邮件发送相关
    else if (appProtocol === 'SMTP' || srcPort === 25 || dstPort === 25 || srcPort === 587 || dstPort === 587) {
        if (info.includes('ehlo') || info.includes('helo')) {
            description = 'SMTP握手 - 邮件客户端与服务器建立连接';
        } else if (info.includes('auth')) {
            description = 'SMTP认证 - 验证发件人身份';
        } else if (info.includes('mail from')) {
            description = 'SMTP发件人 - 告诉服务器邮件从哪里来';
        } else if (info.includes('rcpt to')) {
            description = 'SMTP收件人 - 告诉服务器邮件要发给谁';
        } else if (info.includes('data')) {
            description = 'SMTP邮件数据 - 传输邮件的正文内容';
        } else {
            description = 'SMTP邮件发送 - 用于发送电子邮件的协议';
        }
    }
    
    // POP3邮件接收相关
    else if (appProtocol === 'POP3' || srcPort === 110 || dstPort === 110) {
        if (info.includes('user') || info.includes('pass')) {
            description = 'POP3登录 - 登录邮箱的验证过程';
        } else if (info.includes('list')) {
            description = 'POP3邮件列表 - 查看邮箱里的邮件列表';
        } else if (info.includes('retr')) {
            description = 'POP3邮件下载 - 把邮件从服务器下载到本地电脑';
        } else if (info.includes('dele')) {
            description = 'POP3邮件删除 - 删除邮箱服务器上的邮件';
        } else {
            description = 'POP3邮件接收 - 从邮箱服务器下载邮件的协议';
        }
    }
    
    // IMAP邮件访问相关
    else if (appProtocol === 'IMAP' || srcPort === 143 || dstPort === 143) {
        if (info.includes('login') || info.includes('authenticate')) {
            description = 'IMAP认证 - 登录邮箱的验证过程';
        } else if (info.includes('select')) {
            description = 'IMAP邮箱选择 - 选择要查看的文件夹（如收件箱、发件箱）';
        } else if (info.includes('fetch')) {
            description = 'IMAP邮件获取 - 从服务器读取邮件内容';
        } else {
            description = 'IMAP邮件访问 - 在服务器上管理邮件（如移动、标记）的协议';
        }
    }
    
    // SSH安全远程登录
    else if (appProtocol === 'SSH' || protocol === 'SSH' || srcPort === 22 || dstPort === 22) {
        description = 'SSH安全连接 - 加密的远程登录协议，用于安全管理服务器';
    }
    
    // Telnet远程登录
    else if (appProtocol === 'Telnet' || protocol === 'Telnet' || srcPort === 23 || dstPort === 23) {
        description = 'Telnet远程连接 - 早期的远程登录协议（不加密，现在很少用）';
    }
    
    // DNS域名解析
    else if (appProtocol === 'DNS' || srcPort === 53 || dstPort === 53) {
        if (info.includes('query')) {
            description = 'DNS查询 - 询问域名（如www.baidu.com）对应的IP地址';
        } else if (info.includes('response')) {
            description = 'DNS响应 - 返回域名对应的IP地址（如114.114.114.114）';
        } else {
            description = 'DNS域名解析 - 把网站域名转换成IP地址的服务（类似电话簿）';
        }
    }
    
    // ICMP网络控制消息
    else if (protocol === 'ICMP') {
        if (info.includes('echo request')) {
            description = 'ICMP回显请求 - 就是"ping"命令，测试网络是否连通';
        } else if (info.includes('echo reply')) {
            description = 'ICMP回显响应 - 对"ping"请求的回复（表示网络通了）';
        } else if (info.includes('destination unreachable')) {
            description = 'ICMP目标不可达 - 表示无法到达目标地址（如网络不通）';
        } else if (info.includes('time exceeded')) {
            description = 'ICMP超时 - 数据传输时间太长，请求超时了';
        } else {
            description = 'ICMP控制消息 - 网络诊断工具，用于检查网络故障';
        }
    }
    
    // ARP地址解析协议
    else if (protocol === 'ARP') {
        if (info.includes('request')) {
            description = 'ARP请求 - 询问目标IP地址对应的MAC地址（找谁）';
        } else if (info.includes('reply')) {
            description = 'ARP响应 - 回复自己的IP地址和MAC地址（我在这）';
        } else {
            description = 'ARP地址解析 - 将IP地址转换为MAC地址的协议（类似门牌对应门牌号）';
        }
    }
    
    // LLDP链路层发现协议
    else if (protocol === 'LLDP') {
        description = 'LLDP设备发现 - 用于网络设备之间交换设备信息，如设备名称、端口信息、系统信息等（类似设备自我介绍）';
    }
    
    // mDNS多播DNS
    else if (appProtocol === 'MDNS' || srcPort === 5353 || dstPort === 5353) {
        description = 'mDNS本地解析 - 本地网络里的设备发现（如打印机自动连接）';
    }
    
    // SSDP简单服务发现
    else if (appProtocol === 'SSDP' || srcPort === 1900 || dstPort === 1900) {
        if (info.includes('m-search')) {
            description = 'SSDP服务搜索 - 在局域网里找设备（如智能电视、路由器）';
        } else if (info.includes('notify')) {
            description = 'SSDP服务通告 - 设备告诉大家"我在这里"';
        } else {
            description = 'SSDP服务发现 - 自动找到家里的智能设备';
        }
    }
    
    // WS-Discovery Web服务发现
    else if (appProtocol === 'WS-Discovery' || srcPort === 3702 || dstPort === 3702) {
        if (info.includes('Resolve')) {
            description = 'WS-Discovery Resolve - 查找设备的网络地址';
        } else if (info.includes('Probe')) {
            description = 'WS-Discovery Probe - 搜索网络中的设备';
        } else if (info.includes('Hello')) {
            description = 'WS-Discovery Hello - 设备说"我加入网络了"';
        } else if (info.includes('Bye')) {
            description = 'WS-Discovery Bye - 设备说"我离开网络了"';
        } else {
            description = 'WS-Discovery Message - 智能设备之间的通信协议';
        }
    }
    
    // DHCPv6协议
    else if (appProtocol === 'DHCPv6' || srcPort === 546 || dstPort === 546 || srcPort === 547 || dstPort === 547) {
        if (info.includes('SOLICIT')) {
            description = 'DHCPv6 SOLICIT - 设备请求IPv6网络地址';
        } else if (info.includes('ADVERTISE')) {
            description = 'DHCPv6 ADVERTISE - 服务器回应地址请求';
        } else if (info.includes('REQUEST')) {
            description = 'DHCPv6 REQUEST - 设备请求特定的IPv6地址';
        } else if (info.includes('REPLY')) {
            description = 'DHCPv6 REPLY - 服务器分配IPv6地址给设备';
        } else if (info.includes('RELEASE')) {
            description = 'DHCPv6 RELEASE - 设备释放IPv6地址';
        } else {
            description = 'DHCPv6消息 - 为IPv6网络分配地址的协议';
        }
    }
    
    // NTP协议
    else if (appProtocol === 'NTP' || srcPort === 123 || dstPort === 123) {
        if (info.includes('Client')) {
            description = 'NTP客户端请求 - 设备向时间服务器要当前时间';
        } else if (info.includes('Server')) {
            description = 'NTP服务器响应 - 时间服务器返回准确时间';
        } else if (info.includes('Broadcast')) {
            description = 'NTP广播消息 - 时间服务器向所有设备广播时间';
        } else {
            description = 'NTP时间同步 - 让电脑/手机时间保持准确的协议';
        }
    }
    
    // NBNS NetBIOS名称服务
    else if (appProtocol === 'NBNS' || srcPort === 137 || dstPort === 137) {
        description = 'NBNS名称解析 - 老式局域网里设备名字和IP地址的转换';
    }
    
    // LLMNR链路本地多播名称解析
    else if (appProtocol === 'LLMNR' || srcPort === 5355 || dstPort === 5355) {
        description = 'LLMNR本地名称解析 - 本地网络里快速查找设备的协议';
    }
    
    // BROWSER浏览器服务协议
    else if (appProtocol === 'BROWSER') {
        description = 'BROWSER服务 - 老式Windows网络里的设备发现协议';
    }
    
    // ICMPv6网络控制消息
    else if (protocol === 'ICMPv6') {
        if (info.includes('echo request')) {
            description = 'ICMPv6回显请求 - IPv6网络的"ping"测试，检查网络是否连通';
        } else if (info.includes('echo reply')) {
            description = 'ICMPv6回显响应 - 对IPv6网络"ping"的回复';
        } else if (info.includes('neighbor solicitation')) {
            description = 'ICMPv6邻居请求 - 查找邻居设备的硬件地址';
        } else if (info.includes('neighbor advertisement')) {
            description = 'ICMPv6邻居通告 - 告诉邻居设备自己的硬件地址';
        } else if (info.includes('router solicitation')) {
            description = 'ICMPv6路由器请求 - 设备找网络里的路由器';
        } else if (info.includes('router advertisement')) {
            description = 'ICMPv6路由器通告 - 路由器告诉设备网络信息';
        } else {
            description = 'ICMPv6控制消息 - IPv6网络里的诊断和控制工具';
        }
    }
    
    // IGMP组播管理
    else if (protocol === 'IGMP') {
        if (info.includes('membership query')) {
            description = 'IGMP成员查询 - 路由器问谁想接收组播数据';
        } else if (info.includes('membership report')) {
            description = 'IGMP成员报告 - 设备说"我想接收组播数据"';
        } else {
            description = 'IGMP组播控制 - 管理网络直播、视频会议等数据传输';
        }
    }
    
    // TCP传输控制协议
    else if (protocol === 'TCP') {
        if (info.includes('syn') && !info.includes('ack')) {
            description = 'TCP连接请求 - 设备想和另一台设备建立连接（敲门）';
        } else if (info.includes('syn') && info.includes('ack')) {
            description = 'TCP连接确认 - 对方同意建立连接（请进）';
        } else if (info.includes('ack') && !info.includes('syn')) {
            description = 'TCP确认数据包 - 告诉对方"我收到数据了"';
        } else if (info.includes('fin')) {
            description = 'TCP连接关闭 - 告诉对方"我要结束连接了"';
        } else if (info.includes('rst')) {
            description = 'TCP连接重置 - 突然断开连接（挂电话）';
        } else if (info.includes('psh')) {
            description = 'TCP推送数据 - 立即发送紧急数据';
        } else {
            description = 'TCP数据传输 - 可靠的网络连接协议（如浏览网页、发送邮件）';
        }
    }
    
    // UDP用户数据报协议
    else if (protocol === 'UDP') {
        // 基于端口识别特定UDP协议
        if (srcPort === 53 || dstPort === 53) {
            description = 'UDP DNS查询 - 快速查询域名的协议';
        } else if (srcPort === 67 || dstPort === 67 || srcPort === 68 || dstPort === 68) {
            description = 'DHCP动态配置 - 自动获取IP地址的协议';
        } else if (srcPort === 161 || dstPort === 161) {
            description = 'SNMP管理 - 监控网络设备（如路由器）的协议';
        } else if (srcPort === 69 || dstPort === 69) {
            description = 'TFTP简单文件传输 - 用于简单文件传输的轻量级协议';
        } else {
            description = 'UDP数据传输 - 快速但可能丢包的传输协议（如视频通话、游戏）';
        }
    }
    
    // SNMP简单网络管理协议
    else if (appProtocol === 'SNMP' || srcPort === 161 || dstPort === 161 || srcPort === 162 || dstPort === 162) {
        if (info.includes('get') || info.includes('set')) {
            description = 'SNMP管理操作 - 查询或修改网络设备配置';
        } else if (info.includes('trap')) {
            description = 'SNMP陷阱 - 网络设备主动报告故障或事件';
        } else {
            description = 'SNMP网络管理 - 监控和管理网络设备的协议';
        }
    }
    
    // DHCP动态主机配置协议
    else if (appProtocol === 'DHCP' || srcPort === 67 || srcPort === 68 || dstPort === 67 || dstPort === 68) {
        if (info.includes('discover')) {
            description = 'DHCP发现 - 设备寻找DHCP服务器获取IP地址';
        } else if (info.includes('offer')) {
            description = 'DHCP提供 - 服务器提供IP地址给设备';
        } else if (info.includes('request')) {
            description = 'DHCP请求 - 设备请求特定IP地址';
        } else if (info.includes('ack')) {
            description = 'DHCP确认 - 服务器确认分配IP地址';
        } else if (info.includes('release')) {
            description = 'DHCP释放 - 设备释放IP地址';
        } else {
            description = 'DHCP自动配置 - 为设备自动分配IP地址的协议';
        }
    }
    
    // TFTP简单文件传输协议
    else if (appProtocol === 'TFTP' || srcPort === 69 || dstPort === 69) {
        if (info.includes('read request')) {
            description = 'TFTP读请求 - 从服务器下载文件';
        } else if (info.includes('write request')) {
            description = 'TFTP写请求 - 向服务器上传文件';
        } else {
            description = 'TFTP简单传输 - 用于小型文件传输的轻量级协议';
        }
    }
    
    // SMB/CIFS文件共享协议
    else if (appProtocol === 'SMB' || appProtocol === 'CIFS' || srcPort === 445 || dstPort === 445) {
        description = 'SMB文件共享 - Windows网络中的文件和打印机共享协议';
    }
    
    // RDP远程桌面
    else if (srcPort === 3389 || dstPort === 3389) {
        description = 'RDP远程桌面 - 远程控制另一台Windows电脑的协议';
    }
    
    // PostgreSQL数据库
    else if (srcPort === 5432 || dstPort === 5432) {
        description = 'PostgreSQL数据库 - 一种关系型数据库的通信协议';
    }
    
    // MySQL数据库
    else if (srcPort === 3306 || dstPort === 3306) {
        description = 'MySQL数据库 - 常用的网站数据库通信协议';
    }
    
    // Redis缓存
    else if (srcPort === 6379 || dstPort === 6379) {
        description = 'Redis缓存 - 快速存储数据的缓存系统通信';
    }
    
    // HTTP/HTTPS代理
    else if (srcPort === 8080 || dstPort === 8080) {
        description = 'HTTP代理 - 通过中间人转发网页请求的协议';
    } else if (srcPort === 8443 || dstPort === 8443) {
        description = 'HTTPS代理 - 加密的代理转发协议';
    }
    
    // SAT-EXPAK协议
    else if (appProtocol === 'SAT-EXPAK' || protocol === 'SAT-EXPAK') {
        description = 'SAT-EXPAK协议 - 卫星通信中用于扩展数据传输的协议';
    }
    
    // 其他应用层协议
    else if (appProtocol) {
        // 避免显示"Unknown协议 - 应用层协议通信"
        if (appProtocol !== 'Unknown') {
            description = `${appProtocol}协议 - 特定应用程序使用的通信协议`;
        }
    }
    
    // 通用情况
    else {
        description = `${protocol}数据包 - 网络中传输的数据单元`;
    }
    
    return description;
}

function updatePacketsList(packets) {
    const tbody = document.getElementById('packetsBody');
    const table = document.querySelector('#packets .packets-table');
    
    // 找到数据包表格的父容器，添加结果计数
    const packetsContainer = document.getElementById('packets');
    let resultCountElement = packetsContainer.querySelector('.result-count');
    
    if (!resultCountElement) {
        // 如果结果计数元素不存在，创建它
        resultCountElement = document.createElement('div');
        resultCountElement.className = 'result-count';
        resultCountElement.style.marginBottom = '10px';
        resultCountElement.style.color = '#666';
        
        // 插入到表格之前
        table.parentNode.insertBefore(resultCountElement, table);
    }
    
    // 更新结果计数
    resultCountElement.textContent = `共计查询到 ${packets.length} 条数据包`;
    
    if (packets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="14" style="text-align: center; color: #666;">未找到数据包</td></tr>';
        return;
    }
    
    // 为每个数据包生成协议栈链
    packets.forEach(packet => {
        // 优先使用解析器中已经设置好的协议链
        if (!packet.protocolChain || !packet.protocolChain.includes(' -> ')) {
            // 如果没有，重新构建协议栈链
            const protocolChain = [];
            
            // 检查是否为非IP协议（USB、BLE、HCI_USB等）
            if (packet.protocol === 'ARP') {
                // ARP协议直接显示
                protocolChain.push('ARP');
            } else if (packet.protocol.startsWith('USB') || packet.protocol.startsWith('BLE') || packet.protocol === 'HCI_USB') {
                // USB或BLE相关协议，直接使用其协议类型
                protocolChain.push(packet.protocol);
            } else {
                // IP协议
                const networkProtocol = packet.layers?.network?.version === 6 ? 'IPv6' : 'IP';
                protocolChain.push(networkProtocol);
                
                // 传输层协议
                const transportProtocol = packet.layers?.transport?.type || packet.protocol;
                protocolChain.push(transportProtocol);
                
                // 应用层协议
                if (packet.layers?.application) {
                    // 检查是否有多层应用协议（如TLS over HTTP）
                    let appProtocol = packet.layers.application.protocol;
                    if (appProtocol === 'HTTPS') {
                        // HTTPS协议展开为TCP -> TLS -> HTTP
                        protocolChain.pop(); // 移除TCP
                        protocolChain.push('TCP');
                        protocolChain.push('TLS');
                        protocolChain.push('HTTP');
                    } else if (appProtocol === 'TLS' && packet.layers.application.data) {
                        // TLS包裹的HTTP
                        protocolChain.push('HTTP');
                    } else {
                        // 只有当应用层协议不是"Unknown"时才添加到协议链中
                        if (appProtocol !== 'Unknown') {
                            protocolChain.push(appProtocol);
                        }
                    }
                }
            }
            
            // 生成协议栈链字符串
            packet.protocolChain = protocolChain.join(' -> ');
        }
    });
    
    // 检查哪些列的值全部相同
    const columns = [
        { name: 'uniqueId', index: 1, getter: packet => packet.uniqueId || '-' },
        { name: 'srcIp', index: 4, getter: packet => packet.srcIp || '-' },
        { name: 'srcPort', index: 5, getter: packet => packet.layers?.transport?.srcPort || '-' },
        { name: 'dstIp', index: 6, getter: packet => packet.dstIp || '-' },
        { name: 'dstPort', index: 7, getter: packet => packet.layers?.transport?.dstPort || '-' },
        { name: 'protocolChain', index: 8, getter: packet => packet.protocolChain || '-' },
        { name: 'streamId', index: 9, getter: packet => packet.streamId || '-' }
    ];
    
    // 计算哪些列的值全部相同
    const allSameColumns = columns.filter(column => {
        if (packets.length < 2) return false;
        const firstValue = column.getter(packets[0]);
        return packets.every(packet => column.getter(packet) === firstValue);
    });
    
    // 生成列样式
    const getCellStyle = (columnIndex) => {
        const column = allSameColumns.find(col => col.index === columnIndex);
        return column ? 'background-color: #e8f5e8; color: #2e7d32; font-weight: bold;' : '';
    };
    
    // 计算分页数据
    const startIndex = pageSize === Infinity ? 0 : (currentPage - 1) * pageSize;
    const endIndex = pageSize === Infinity ? packets.length : startIndex + pageSize;
    const currentPageData = packets.slice(startIndex, endIndex);
    
    let html = '';
    
    // 检查数据包是否包含关键字的函数
    function checkKeywordMatches(packet) {
        const matches = [];
        
        // 定义需要检查的数据包属性
        const packetAttributes = [
            { name: 'uniqueId', value: packet.uniqueId },
            { name: 'srcIp', value: packet.srcIp },
            { name: 'srcPort', value: packet.layers?.transport?.srcPort },
            { name: 'dstIp', value: packet.dstIp },
            { name: 'dstPort', value: packet.layers?.transport?.dstPort },
            { name: 'protocol', value: packet.protocol },
            { name: 'protocolChain', value: packet.protocolChain },
            { name: 'info', value: packet.info },
            { name: 'functionDesc', value: getPacketFunctionDescription(packet) },
            { name: 'timestamp', value: packet.timestamp },
            { name: 'packetLen', value: packet.packetLen },
            { name: 'streamId', value: packet.streamId }
        ];
        
        // 检查应用层数据
        if (packet.layers?.application) {
            const appData = packet.layers.application;
            packetAttributes.push(
                { name: 'applicationProtocol', value: appData.protocol },
                { name: 'applicationInfo', value: appData.info },
                { name: 'httpMethod', value: appData.httpInfo?.method },
                { name: 'httpUrl', value: appData.httpInfo?.url },
                { name: 'httpHeaders', value: JSON.stringify(appData.httpInfo?.headers) },
                { name: 'httpBody', value: appData.httpInfo?.body },
                { name: 'httpStatus', value: appData.httpInfo?.status },
                { name: 'rawData', value: appData.raw }
            );
        }
        
        // 检查传输层数据
        if (packet.layers?.transport) {
            const transportData = packet.layers.transport;
            packetAttributes.push(
                { name: 'transportType', value: transportData.type },
                { name: 'transportInfo', value: transportData.info }
            );
        }
        
        // 检查网络层数据
        if (packet.layers?.network) {
            const networkData = packet.layers.network;
            packetAttributes.push(
                { name: 'networkVersion', value: networkData.version },
                { name: 'networkInfo', value: networkData.info }
            );
        }
        
        // 检查链路层数据
        if (packet.layers?.link) {
            const linkData = packet.layers.link;
            packetAttributes.push(
                { name: 'linkType', value: linkData.type },
                { name: 'linkInfo', value: linkData.info }
            );
        }
        
        // 遍历所有属性和关键字，检查是否匹配（仅当开关开启时）
        if (isKeywordMatchingEnabled()) {
            packetAttributes.forEach(attr => {
                if (attr.value === null || attr.value === undefined || attr.value === '-') {
                    return;
                }
                
                const attrValue = String(attr.value).toLowerCase();
                
                keywords.forEach(keyword => {
                    const keywordLower = keyword.toLowerCase();
                    if (attrValue.includes(keywordLower)) {
                        matches.push({
                            keyword: keyword,
                            attribute: attr.name,
                            value: attr.value
                        });
                    }
                });
            });
        }
        
        return matches;
    }
    
    currentPageData.forEach((packet, index) => {
        // 获取原始索引，用于showPacketDetails函数
        const originalIndex = startIndex + index;
        // 获取流ID
        const streamId = (packet.streamId || '-').toString();
        // 获取唯一ID
        const uniqueId = (packet.uniqueId || '-').toString();
        // 获取源端口和目标端口
        const srcPort = (packet.layers?.transport?.srcPort || '-').toString();
        const dstPort = (packet.layers?.transport?.dstPort || '-').toString();
        // 获取数据包功能介绍
        const functionDesc = getPacketFunctionDescription(packet);
        
        // 检查关键字匹配
        const keywordMatches = checkKeywordMatches(packet);
        
        // 生成关键字匹配显示内容
        let keywordMatchesHtml = '';
        if (keywordMatches.length > 0) {
            keywordMatchesHtml = keywordMatches.map(match => {
                return `<div style="margin-bottom: 2px; font-size: 11px;"><strong>${match.keyword}:</strong> ${match.attribute}</div>`;
            }).join('');
        } else {
            keywordMatchesHtml = '-';
        }
        
        // 确保所有文本值都是字符串类型
        const textSrcIp = (packet.srcIp || '').toString();
        const textDstIp = (packet.dstIp || '').toString();
        const textProtocolChain = (packet.protocolChain || '').toString();
        const textInfo = (packet.info || '').toString();
        const textFunctionDesc = (functionDesc || '').toString();
        
        // 应用高亮
        const highlightedUniqueId = highlightKeyword(uniqueId, currentSearchKeyword);
        const highlightedSrcIp = highlightKeyword(textSrcIp, currentSearchKeyword);
        const highlightedSrcPort = highlightKeyword(srcPort, currentSearchKeyword);
        const highlightedDstIp = highlightKeyword(textDstIp, currentSearchKeyword);
        const highlightedDstPort = highlightKeyword(dstPort, currentSearchKeyword);
        const highlightedProtocolChain = highlightKeyword(textProtocolChain, currentSearchKeyword);
        const highlightedStreamId = highlightKeyword(streamId, currentSearchKeyword);
        const highlightedPacketLen = highlightKeyword(packet.packetLen.toString(), currentSearchKeyword);
        const highlightedFunctionDesc = highlightKeyword(textFunctionDesc, currentSearchKeyword);
        const highlightedInfo = highlightKeyword(textInfo, currentSearchKeyword);
        const highlightedTimestamp = highlightKeyword(PcapngParser.formatTime(packet.timestamp, true), currentSearchKeyword);
        const highlightedNumber = highlightKeyword((originalIndex + 1).toString(), currentSearchKeyword);
        
        html += `
            <tr>
                <td>
                    <div style="display: flex; gap: 5px;">
                        <button onclick="showPacketDetails(${originalIndex})" style="padding: 4px 8px; background-color: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">详情</button>
                        ${streamId !== '-' ? `<button onclick="showFlowConversation(${streamId})" style="padding: 4px 8px; background-color: #2ecc71; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">流对话</button>` : ''}
                    </div>
                </td>
                <td style="${getCellStyle(1)}">${highlightedUniqueId}</td>
                <td>${highlightedNumber}</td>
                <td>${highlightedTimestamp}</td>
                <td style="${getCellStyle(4)}">${highlightedSrcIp}</td>
                <td style="${getCellStyle(5)}">${highlightedSrcPort}</td>
                <td style="${getCellStyle(6)}">${highlightedDstIp}</td>
                <td style="${getCellStyle(7)}">${highlightedDstPort}</td>
                <td style="${getCellStyle(8)}">${highlightedProtocolChain}</td>
                <td style="${getCellStyle(9)}">${highlightedStreamId}</td>
                <td>${highlightedPacketLen}</td>
                <td style="color: #2c3e50; font-weight: 500;">${highlightedFunctionDesc}</td>
                <td>${highlightedInfo}</td>
                <td style="max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: help;" title="${keywordMatches.map(match => `${match.keyword}: ${match.attribute} = ${match.value}`).join('\n')}">${keywordMatchesHtml}</td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
    
    // 为表头添加样式
    const headers = table.querySelectorAll('thead th');
    headers.forEach((header, index) => {
        const column = allSameColumns.find(col => col.index === index);
        if (column) {
            header.style.backgroundColor = '#c8e6c9';
            header.style.color = '#1b5e20';
            header.style.fontWeight = 'bold';
        } else {
            header.style.backgroundColor = '';
            header.style.color = '';
            header.style.fontWeight = '';
        }
    });
    
    // 更新分页信息
    if (currentListType === 'packets') {
        updatePagination();
    }
    
    // 重新初始化表格拖拽功能
    reinitTableResizable();
}

// HTML转义函数，防止邮件地址等被当作HTML标签解析
function htmlEscape(str) {
    if (typeof str !== 'string') return str;
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// 切换设置面板显示/隐藏


// 更新关键字列表显示
function updateKeywordList() {
    const keywordList = document.getElementById('keywordList');
    if (!keywordList) return;
    
    let html = '';
    if (keywords.length === 0) {
        html = '<div style="color: #666; text-align: center; padding: 10px;">暂无关键字</div>';
    } else {
        keywords.forEach((keyword, index) => {
            html += `
                <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px; border-bottom: 1px solid #eee; font-size: 14px;">
                    <span>${htmlEscape(keyword)}</span>
                    <button onclick="deleteKeyword(${index})" style="background-color: #e74c3c; color: white; border: none; border-radius: 4px; padding: 4px 8px; cursor: pointer; font-size: 12px;">删除</button>
                </div>
            `;
        });
    }
    
    keywordList.innerHTML = html;
}

// 添加关键字
function addKeyword() {
    const newKeywordInput = document.getElementById('newKeyword');
    if (!newKeywordInput) return;
    
    const newKeyword = newKeywordInput.value.trim();
    if (newKeyword === '') {
        alert('关键字不能为空');
        return;
    }
    
    if (keywords.includes(newKeyword)) {
        alert('关键字已存在');
        return;
    }
    
    keywords.push(newKeyword);
    newKeywordInput.value = '';
    updateKeywordList();
    updateListWithPagination(); // 更新数据包列表显示，包含分页处理
}

// 删除关键字
function deleteKeyword(index) {
    keywords.splice(index, 1);
    updateKeywordList();
    updateListWithPagination(); // 更新数据包列表显示，包含分页处理
}

// 保存设置
function saveSettings() {
    // 保存关键字
    localStorage.setItem('webshark_keywords', JSON.stringify(keywords));
    
    // 保存开关状态
    const toggle = document.getElementById('keywordMatchToggle');
    if (toggle) {
        localStorage.setItem('webshark_keyword_toggle', toggle.checked);
    }
    
    alert('设置已保存');
}

// 还原默认关键字
function restoreDefaultKeywords() {
    if (confirm('确定要还原为系统默认关键字吗？当前自定义关键字将被覆盖。')) {
        // 恢复默认关键字
        keywords = [...DEFAULT_KEYWORDS];
        
        // 更新关键字列表UI
        updateKeywordList();
        
        // 更新数据包列表显示
        updateListWithPagination();
        
        // 保存到localStorage
        localStorage.setItem('webshark_keywords', JSON.stringify(keywords));
        
        alert('已还原为系统默认关键字');
    }
}

// 检查关键字匹配开关是否开启
function isKeywordMatchingEnabled() {
    // 首先检查localStorage中保存的状态
    const savedToggle = localStorage.getItem('webshark_keyword_toggle');
    let isEnabled = savedToggle === 'true' || savedToggle === true;
    
    // 如果页面上有开关元素，优先使用页面上的状态
    const toggle = document.getElementById('keywordMatchToggle');
    if (toggle) {
        isEnabled = toggle.checked;
    }
    
    return isEnabled;
}

// 初始化关键字设置
function initSettings() {
    // 从localStorage加载保存的关键字设置
    const savedKeywords = localStorage.getItem('webshark_keywords');
    if (savedKeywords) {
        try {
            const parsedKeywords = JSON.parse(savedKeywords);
            if (Array.isArray(parsedKeywords)) {
                keywords = parsedKeywords;
            }
        } catch (error) {
            console.error('加载保存的关键字设置失败:', error);
        }
    }
    
    // 从localStorage加载保存的开关状态
    const savedToggle = localStorage.getItem('webshark_keyword_toggle');
    const toggle = document.getElementById('keywordMatchToggle');
    if (toggle) {
        // 默认状态为开启
        const isEnabled = savedToggle === 'true' || savedToggle === true || savedToggle === null;
        toggle.checked = isEnabled;
        // 手动触发change事件，确保UI正确更新
        toggle.dispatchEvent(new Event('change'));
    }
}

// 搜索关键字高亮函数
function highlightKeyword(text, keyword) {
    if (!keyword || !text || typeof text !== 'string') return htmlEscape(text);
    
    // 先转义关键字和文本，防止正则表达式错误
    const escapedKeyword = htmlEscape(keyword);
    const escapedText = htmlEscape(text);
    
    // 创建不区分大小写的正则表达式
    const regex = new RegExp(`(${escapedKeyword})`, 'gi');
    
    // 替换为高亮的HTML
    return escapedText.replace(regex, '<span style="font-weight: bold; color: red;">$1</span>');
}

// 全局变量用于保存当前搜索关键字
let currentSearchKeyword = '';
let currentFlowSearchKeyword = '';
let currentHttpSearchKeyword = '';

// URL解码函数，支持双重URL编码
function urlDecode(str) {
    if (typeof str !== 'string') return str;
    try {
        // 尝试多次解码，直到无法再解码或达到最大次数（防止无限循环）
        let decoded = str;
        let prevDecoded;
        let count = 0;
        const maxTries = 5;
        
        do {
            prevDecoded = decoded;
            decoded = decodeURIComponent(decoded);
            count++;
        } while (decoded !== prevDecoded && count < maxTries);
        
        return decoded;
    } catch (error) {
        // 如果解码失败，返回原始字符串
        return str;
    }
}

// 更新流列表
function updateStreamsList(streams) {
    const tbody = document.getElementById('flowsBody');
    const table = tbody.closest('table');
    
    // 找到流列表的父容器，添加结果计数
    const flowsContainer = document.getElementById('flows');
    let resultCountElement = flowsContainer.querySelector('.flow-result-count');
    
    if (!resultCountElement) {
        // 如果结果计数元素不存在，创建它
        resultCountElement = document.createElement('div');
        resultCountElement.className = 'flow-result-count';
        resultCountElement.style.marginBottom = '10px';
        resultCountElement.style.color = '#666';
        
        // 插入到流列表之前
        const streamSection = flowsContainer.querySelector('.flow-section');
        streamSection.parentNode.insertBefore(resultCountElement, streamSection);
    }
    
    let streamArray;
    
    // 优先使用排序后的流数组，保持排序状态
    // 只有在没有排序结果或传入了新的流列表时，才使用传入的流列表
    if (sortedStreamArray && sortedStreamArray.length > 0 && 
        streams && typeof streams === 'object' && 
        !Array.isArray(streams) && 
        Object.keys(streams).length === sortedStreamArray.length) {
        // 使用之前保存的排序后的流数组，保持排序状态
        streamArray = sortedStreamArray;
    } else if (Array.isArray(streams)) {
        // 如果传入的是数组，直接使用
        streamArray = streams;
    } else {
        // 如果是对象，转换为数组
        streamArray = Object.values(streams);
    }
    
    // 更新结果计数
    resultCountElement.textContent = `共计查询到 ${streamArray.length} 条流`;
    
    if (streamArray.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #666;">未找到流信息</td></tr>';
        return;
    }
    
    // 优化：预先计算所有流的协议值，避免重复计算
    const streamProtocolMap = new Map();
    
    // 计算哪些列的值全部相同
    const allSameColumns = [];
    
    // 只有当流数量大于1时才需要检查列值是否全部相同
    if (streamArray.length > 1) {
        // 预计算所有流的协议值
        streamArray.forEach(stream => {
            if (!streamProtocolMap.has(stream)) {
                // 使用缓存的协议值或计算一次
                if (stream._cachedProtocol) {
                    streamProtocolMap.set(stream, stream._cachedProtocol);
                } else {
                    const streamPackets = getStreamPackets(stream);
                    let protocol = 'Unknown';
                    
                    if (streamPackets.length > 0) {
                        const appProtocols = streamPackets
                            .filter(packet => packet.layers?.application)
                            .map(packet => packet.layers.application.protocol)
                            .filter(Boolean)
                            .filter(protocol => protocol !== 'Unknown'); // 排除Unknown协议
                        
                        // 找出出现次数最多的协议
                        if (appProtocols.length > 0) {
                            const protocolCounts = appProtocols.reduce((acc, curr) => {
                                acc[curr] = (acc[curr] || 0) + 1;
                                return acc;
                            }, {});
                            
                            protocol = Object.entries(protocolCounts)
                                .sort(([,a], [,b]) => b - a)
                                [0][0];
                        } else {
                            protocol = streamPackets[0].protocol;
                        }
                    }
                    
                    stream._cachedProtocol = protocol; // 缓存结果
                    streamProtocolMap.set(stream, protocol);
                }
            }
        });
        
        // 检查协议列的值是否全部相同
        const firstProtocol = streamProtocolMap.get(streamArray[0]);
        const allProtocolsSame = streamArray.every(stream => streamProtocolMap.get(stream) === firstProtocol);
        
        if (allProtocolsSame) {
            allSameColumns.push({ name: 'protocol', index: 5 });
        }
    }
    
    // 生成列样式
    const getCellStyle = (columnIndex) => {
        const column = allSameColumns.find(col => col.index === columnIndex);
        return column ? 'background-color: #e8f5e8; color: #2e7d32; font-weight: bold;' : '';
    };
    
    // 计算分页数据
    const startIndex = pageSize === Infinity ? 0 : (currentPage - 1) * pageSize;
    const endIndex = pageSize === Infinity ? streamArray.length : startIndex + pageSize;
    const currentPageStreamArray = streamArray.slice(startIndex, endIndex);
    
    let html = '';
    currentPageStreamArray.forEach(stream => {
        const packetCount = stream.packets.length;
        
        // 获取流中完整的数据包对象
        const streamPackets = getStreamPackets(stream);
        
        // 使用预缓存的总长度，避免重复计算
        const totalLength = stream._cachedTotalLength || 0;
        
        // 使用预缓存的协议，避免重复计算
        const protocol = stream._cachedProtocol;
        
        // 计算协议统计信息（使用缓存避免重复计算）
        let protocolStats, protocolStatsHtml;
        if (stream._cachedProtocolStats) {
            protocolStats = stream._cachedProtocolStats;
            protocolStatsHtml = stream._cachedProtocolStatsHtml;
        } else {
            protocolStats = {};
            stream.packets.forEach(packetId => {
                const packet = getPacketById(packetId);
                if (packet) {
                    // 获取协议链中的所有协议
                    let protocols = [];
                    if (packet.protocolChain) {
                        protocols = packet.protocolChain.split(' > ');
                    } else {
                        protocols = [packet.protocol];
                    }
                    
                    // 对于每个协议，统计数量和长度
                    protocols.forEach(protocol => {
                        if (!protocolStats[protocol]) {
                            protocolStats[protocol] = {
                                count: 0,
                                length: 0
                            };
                        }
                        protocolStats[protocol].count++;
                        protocolStats[protocol].length += (packet.packetLen || 0);
                    });
                }
            });
            
            // 计算每个协议的占比
            Object.keys(protocolStats).forEach(protocol => {
                const stats = protocolStats[protocol];
                stats.countPercentage = ((stats.count / packetCount) * 100).toFixed(1);
                stats.lengthPercentage = ((stats.length / totalLength) * 100).toFixed(1);
            });
            
            // 格式化协议统计信息为HTML
            protocolStatsHtml = '';
            Object.entries(protocolStats).forEach(([protocol, stats]) => {
                protocolStatsHtml += `<div style="margin-bottom: 5px;">
                    <strong>${protocol}:</strong> ${stats.count}包 (${stats.countPercentage}%)，
                    ${stats.length}字节 (${stats.lengthPercentage}%)
                </div>`;
            });
            
            // 缓存结果
            stream._cachedProtocolStats = protocolStats;
            stream._cachedProtocolStatsHtml = protocolStatsHtml;
        }
        
        // 应用高亮
        const streamId = stream.id !== undefined ? stream.id : 'undefined';
        const srcAddress = `${stream.srcIp}:${stream.srcPort}`;
        const dstAddress = `${stream.dstIp}:${stream.dstPort}`;
        
        const highlightedStreamId = highlightKeyword(streamId, currentFlowSearchKeyword);
        const highlightedSrcAddress = highlightKeyword(srcAddress, currentFlowSearchKeyword);
        const highlightedDstAddress = highlightKeyword(dstAddress, currentFlowSearchKeyword);
        const highlightedPacketCount = highlightKeyword(packetCount, currentFlowSearchKeyword);
        const highlightedTotalLength = highlightKeyword(totalLength, currentFlowSearchKeyword);
        const highlightedProtocol = highlightKeyword(protocol, currentFlowSearchKeyword);
        
        // 对于SMTP协议，尝试从对话中提取附件信息
        let protocolDetails = '';
        if (protocol === 'SMTP' && stream.conversation) {
            // 提取所有SMTP消息的内容
            const contentParts = stream.conversation.map(msg => msg.info).filter(info => info && typeof info === 'string');
            const fullContent = contentParts.join('\n');
            
            // 简单检测是否有附件
            const hasAttachments = /Content-Disposition:\s*attachment|filename="?[^"\r\n]+"?|Content-Type:[^;\r\n]+;\s*name="?[^"\r\n]+"?/i.test(fullContent);
            
            if (hasAttachments) {
                // 提取附件信息
                let attachmentInfo = [];
                
                // 提取Content-Type信息
                const contentTypeRegex = /Content-Type:\s*([^;\r\n]+)(?:;\s*charset="?([^"\s;]+)"?)?/gi;
                let match;
                while ((match = contentTypeRegex.exec(fullContent)) !== null) {
                    if (match[1]) {
                        let typeInfo = match[1];
                        if (match[2]) {
                            typeInfo += ` (${match[2]})`;
                        }
                        attachmentInfo.push(typeInfo);
                    }
                }
                
                // 提取Content-Transfer-Encoding信息
                const encodingRegex = /Content-Transfer-Encoding:\s*([^\r\n]+)/gi;
                while ((match = encodingRegex.exec(fullContent)) !== null) {
                    if (match[1]) {
                        attachmentInfo.push(match[1]);
                    }
                }
                
                // 提取文件名
                const filenameRegex = /filename="?([^"\r\n]+\.[^"\r\n]+)"?/gi;
                const filenames = [];
                while ((match = filenameRegex.exec(fullContent)) !== null) {
                    if (match[1]) {
                        filenames.push(match[1]);
                    }
                }
                
                // 构建协议详情文本
                if (filenames.length > 0) {
                    protocolDetails = ` ${filenames.length}附件`;
                    if (filenames.length <= 2) {
                        protocolDetails += `: ${filenames.join(', ')}`;
                    }
                }
                
                // 限制显示的信息数量
                if (attachmentInfo.length > 3) {
                    attachmentInfo = attachmentInfo.slice(0, 3).concat('...');
                }
                
                if (attachmentInfo.length > 0) {
                    protocolDetails += ` (${attachmentInfo.join(', ')})`;
                }
            }
        }
        
        html += `
            <tr onclick="selectStream('${streamId}')">
                <td style="font-weight: 500; color: #2c3e50;">${highlightedStreamId}</td>
                <td style="color: #666;">${highlightedSrcAddress}</td>
                <td style="color: #666;">${highlightedDstAddress}</td>
                <td style="font-weight: 600; color: #3498db;">${highlightedPacketCount}</td>
                <td style="font-weight: 600; color: #2e7d32;">${highlightedTotalLength}</td>
                <td style="${getCellStyle(5)} text-transform: uppercase; font-weight: 500;">
                    <span style="background: #e3f2fd; color: #2196f3; padding: 4px 8px; border-radius: 4px; font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 300px; display: inline-block;">${highlightedProtocol}${protocolDetails}</span>
                </td>
                <td style="color: #666; font-size: 12px; vertical-align: top;">${protocolStatsHtml}</td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
    
    // 为表头添加样式
    if (table) {
        const headers = table.querySelectorAll('thead th');
        headers.forEach((header, index) => {
            const column = allSameColumns.find(col => col.index === index);
            if (column) {
                header.style.backgroundColor = '#c8e6c9';
                header.style.color = '#1b5e20';
                header.style.fontWeight = 'bold';
            } else {
                header.style.backgroundColor = '';
                header.style.color = '';
                header.style.fontWeight = '';
            }
        });
    }
    
    // 更新分页信息
    if (currentListType === 'streams') {
        updatePagination();
    }
    
    // 重新初始化表格拖拽功能
    reinitTableResizable();
}

// 选择流并高亮显示
function selectStream(streamId) {
    // 移除所有行的选中状态
    const rows = document.querySelectorAll('#flowsBody tr');
    rows.forEach(row => row.classList.remove('selected'));
    
    // 添加当前行的选中状态
    const clickedRow = event.target.closest('tr');
    if (clickedRow) {
        clickedRow.classList.add('selected');
    }
    
    // 调用原有的显示流对话函数
    showFlowConversation(streamId);
}

// 显示流对话
// 显示流详情（作为showFlowConversation的别名）
function showFlowDetails(streamId) {
    showFlowConversation(streamId);
}

function showFlowConversation(streamId) {
    // 首先切换到流列表标签页，确保用户能看到对话内容
    switchTab('flows');
    
    const conversationDiv = document.getElementById('flowConversation');
    const stream = currentStreams[streamId];
    
    if (!stream || stream.conversation.length === 0) {
        conversationDiv.innerHTML = `
            <div style="text-align: center; padding: 60px 20px; color: #666; max-height: 700px; overflow-y: auto;">
                <p style="margin: 0; font-size: 14px;">此流没有对话记录</p>
            </div>
        `;
        
        // 清除数据包列表
        const packetsTableDiv = document.getElementById('packetsTableContainer');
        if (packetsTableDiv) {
            packetsTableDiv.remove();
        }
        
        return;
    }
    
    // 确定流的主要协议
    let mainProtocol = 'Unknown';
    if (stream.packets.length > 0) {
        const streamPackets = getStreamPackets(stream);
        const appProtocols = streamPackets
            .filter(packet => packet.layers?.application)
            .map(packet => packet.layers.application.protocol)
            .filter(Boolean)
            .filter(protocol => protocol !== 'Unknown'); // 排除Unknown协议
        
        if (appProtocols.length > 0) {
            const protocolCounts = appProtocols.reduce((acc, curr) => {
                // 合并HTTP和HTTPS为同一协议进行统计
                const normalizedProtocol = curr === 'HTTPS' ? 'HTTP' : curr;
                acc[normalizedProtocol] = (acc[normalizedProtocol] || 0) + 1;
                return acc;
            }, {});
            
            mainProtocol = Object.entries(protocolCounts)
                .sort(([,a], [,b]) => b - a)
                [0][0];
        } else {
            // 对于没有应用层协议的流，检查端口是否为HTTP/HTTPS端口
            const firstPacket = streamPackets[0];
            const srcPort = firstPacket.layers?.transport?.srcPort;
            const dstPort = firstPacket.layers?.transport?.dstPort;
            
            // 检查是否为HTTP/HTTPS端口
            const httpPorts = [80, 443, 8080, 8443];
            if (httpPorts.includes(srcPort) || httpPorts.includes(dstPort)) {
                mainProtocol = 'HTTP';
            } else {
                mainProtocol = firstPacket.protocol;
            }
        }
    }
    
    // 直接从SMTP流中提取附件信息的备用函数
    function extractAttachmentsFromStream(messages) {
        const attachments = [];
        
        // 提取所有消息的info字段，因为这包含实际的SMTP内容
        const contentParts = messages.map(msg => msg.info).filter(info => info && typeof info === 'string');
        
        // 合并所有内容部分
        const fullContent = contentParts.join('\n');
        
        // 正则表达式匹配附件信息
        // 1. 首先尝试匹配Content-Disposition头（最可靠的附件标记）
        const contentDispositionRegex = /Content-Disposition:\s*attachment;\s*filename="?([^"]+)"?/gi;
        let match;
        
        while ((match = contentDispositionRegex.exec(fullContent)) !== null) {
            if (match[1]) {
                const attachment = {
                    name: match[1],
                    contentDisposition: match[0],
                    detectedFrom: 'Content-Disposition',
                    contentType: '',
                    charset: '',
                    contentTransferEncoding: ''
                };
                
                // 尝试找到对应的Content-Type和Content-Transfer-Encoding
                const position = match.index;
                
                // 向后查找当前邮件部分的结束（下一个边界或邮件结束）
                const boundaryRegex = /--[\w-]+(?:\r\n|$)/g;
                let nextBoundaryIndex = fullContent.length;
                let boundaryMatch;
                
                // 向前查找最近的邮件边界或邮件开始
                let lastBoundaryIndex = -1;
                boundaryRegex.lastIndex = 0;
                while ((boundaryMatch = boundaryRegex.exec(fullContent)) !== null) {
                    if (boundaryMatch.index < position) {
                        lastBoundaryIndex = boundaryMatch.index;
                    } else {
                        break;
                    }
                }
                
                // 重置边界正则表达式，查找下一个边界
                boundaryRegex.lastIndex = position;
                while ((boundaryMatch = boundaryRegex.exec(fullContent)) !== null) {
                    nextBoundaryIndex = boundaryMatch.index;
                    break;
                }
                
                // 在当前邮件部分查找所有头部
                const currentSection = fullContent.substring(lastBoundaryIndex, nextBoundaryIndex);
                
                // 查找Content-Type，确保是当前部分的最后一个
                const contentTypeRegex = /Content-Type:\s*([^;\r\n]+)(?:;\s*name="?([^"]+)"?)?(?:;\s*charset="?([^"]+)"?)?/gi;
                let contentTypeMatch;
                let lastContentTypeMatch = null;
                
                while ((contentTypeMatch = contentTypeRegex.exec(currentSection)) !== null) {
                    lastContentTypeMatch = contentTypeMatch;
                }
                
                if (lastContentTypeMatch) {
                    attachment.contentType = lastContentTypeMatch[0];
                    // 提取charset
                    if (lastContentTypeMatch[3]) {
                        attachment.charset = lastContentTypeMatch[3];
                    } else {
                        // 尝试从完整的Content-Type中提取charset
                        const charsetMatch = lastContentTypeMatch[0].match(/charset="?([^";\s]+)"?/i);
                        if (charsetMatch && charsetMatch[1]) {
                            attachment.charset = charsetMatch[1];
                        }
                    }
                }
                
                // 查找Content-Transfer-Encoding
                const encodingRegex = /Content-Transfer-Encoding:\s*([^\r\n]+)/i;
                const encodingMatch = currentSection.match(encodingRegex);
                if (encodingMatch) {
                    attachment.contentTransferEncoding = encodingMatch[0];
                }
                
                // 提取文件内容
                // 查找头部结束位置（两个连续的换行符）
                const headersEndIndex = currentSection.indexOf('\r\n\r\n');
                if (headersEndIndex !== -1) {
                    // 提取头部后面的内容作为文件内容
                    let content = currentSection.substring(headersEndIndex + 4); // +4 跳过\r\n\r\n
                    // 移除末尾的换行符和边界标记
                    content = content.replace(/\r\n--[\w-]+(?:\r\n|$)/, '');
                    content = content.trim();
                    
                    attachment.content = content;
                } else {
                    attachment.content = '';
                }
                
                attachments.push(attachment);
            }
        }
        
        // 2. 然后匹配Content-Type头中的文件名（用于可能没有Content-Disposition的情况）
        const contentTypeRegex = /Content-Type:\s*([^;\r\n]+);\s*name="?([^"]+)"?(?:;\s*charset="?([^"]+)"?)?/gi;
        
        while ((match = contentTypeRegex.exec(fullContent)) !== null) {
            if (match[2]) {
                // 检查是否已经存在相同的附件
                const existing = attachments.find(attach => attach.name === match[2]);
                if (!existing) {
                    const attachment = {
                        name: match[2],
                        contentType: match[0],
                        detectedFrom: 'Content-Type',
                        charset: match[3] || '',
                        contentDisposition: '',
                        contentTransferEncoding: ''
                    };
                    
                    // 尝试找到对应的Content-Transfer-Encoding
                    const position = match.index;
                    
                    // 找到当前邮件部分的边界
                    const boundaryRegex = /--[\w-]+(?:\r\n|$)/g;
                    let lastBoundaryIndex = -1;
                    let nextBoundaryIndex = fullContent.length;
                    let boundaryMatch;
                    
                    // 向前查找最近的边界
                    boundaryRegex.lastIndex = 0;
                    while ((boundaryMatch = boundaryRegex.exec(fullContent)) !== null) {
                        if (boundaryMatch.index < position) {
                            lastBoundaryIndex = boundaryMatch.index;
                        } else {
                            nextBoundaryIndex = boundaryMatch.index;
                            break;
                        }
                    }
                    
                    // 提取当前邮件部分
                    const currentSection = fullContent.substring(lastBoundaryIndex, nextBoundaryIndex);
                    
                    // 查找Content-Transfer-Encoding
                    const encodingRegex = /Content-Transfer-Encoding:\s*([^\r\n]+)/i;
                    const encodingMatch = currentSection.match(encodingRegex);
                    if (encodingMatch) {
                        attachment.contentTransferEncoding = encodingMatch[0];
                    }
                    
                    // 提取文件内容
                    const headersEndIndex = currentSection.indexOf('\r\n\r\n');
                    if (headersEndIndex !== -1) {
                        let content = currentSection.substring(headersEndIndex + 4);
                        content = content.replace(/\r\n--[\w-]+(?:\r\n|$)/, '');
                        content = content.trim();
                        
                        attachment.content = content;
                    } else {
                        attachment.content = '';
                    }
                    
                    attachments.push(attachment);
                }
            }
        }
        
        // 3. 直接搜索文件名模式，特别是在多部分边界附近
        const filenameRegex = /filename="?([^"\r\n]+\.(rar|zip|pdf|doc|docx|xls|xlsx|ppt|pptx|exe|jpg|jpeg|png|gif|txt|csv|json))"?/gi;
        
        while ((match = filenameRegex.exec(fullContent)) !== null) {
            if (match[1]) {
                // 检查是否已经存在相同的附件
                const existing = attachments.find(attach => attach.name === match[1]);
                if (!existing) {
                    const attachment = {
                        name: match[1],
                        detectedFrom: 'Direct Filename Match',
                        contentType: '',
                        charset: '',
                        contentDisposition: '',
                        contentTransferEncoding: ''
                    };
                    
                    // 尝试找到对应的Content-Type、Content-Disposition和Content-Transfer-Encoding
                    const position = match.index;
                    const prevContent = fullContent.substring(0, position);
                    
                    // 查找Content-Type
                    const contentTypeMatch = prevContent.match(/Content-Type:\s*([^;\r\n]+)(?:;\s*charset="?([^"]+)"?)/gi);
                    if (contentTypeMatch) {
                        attachment.contentType = contentTypeMatch[contentTypeMatch.length - 1];
                        // 提取charset
                        const charsetMatch = attachment.contentType.match(/charset="?([^";]+)"?/i);
                        if (charsetMatch && charsetMatch[1]) {
                            attachment.charset = charsetMatch[1];
                        }
                    }
                    
                    // 查找Content-Disposition
                    const contentDispositionMatch = prevContent.match(/Content-Disposition:\s*[^;\r\n]+(?:;\s*[^;\r\n]+)*/gi);
                    if (contentDispositionMatch) {
                        attachment.contentDisposition = contentDispositionMatch[contentDispositionMatch.length - 1];
                    }
                    
                    // 查找Content-Transfer-Encoding
                    const encodingMatch = prevContent.match(/Content-Transfer-Encoding:\s*([^\r\n]+)/gi);
                    if (encodingMatch) {
                        attachment.contentTransferEncoding = encodingMatch[encodingMatch.length - 1];
                    }
                    
                    // 提取文件内容
                    // 找到当前邮件部分的边界
                    const boundaryRegex = /--[\w-]+(?:\r\n|$)/g;
                    let lastBoundaryIndex = -1;
                    let nextBoundaryIndex = fullContent.length;
                    let boundaryMatch;
                    
                    // 向前查找最近的边界
                    boundaryRegex.lastIndex = 0;
                    while ((boundaryMatch = boundaryRegex.exec(fullContent)) !== null) {
                        if (boundaryMatch.index < position) {
                            lastBoundaryIndex = boundaryMatch.index;
                        } else {
                            nextBoundaryIndex = boundaryMatch.index;
                            break;
                        }
                    }
                    
                    // 提取当前邮件部分
                    const currentSection = fullContent.substring(lastBoundaryIndex, nextBoundaryIndex);
                    
                    // 查找头部结束位置并提取内容
                    const headersEndIndex = currentSection.indexOf('\r\n\r\n');
                    if (headersEndIndex !== -1) {
                        let content = currentSection.substring(headersEndIndex + 4);
                        content = content.replace(/\r\n--[\w-]+(?:\r\n|$)/, '');
                        content = content.trim();
                        
                        attachment.content = content;
                    } else {
                        attachment.content = '';
                    }
                    
                    attachments.push(attachment);
                }
            }
        }
        
        return attachments;
    }

    // 清理附件内容，移除边界标记和多余空格
    function cleanAttachmentContent(content, boundaryStack) {
        if (!content) return '';
        
        let cleanedContent = content.trim();
        
        // 移除所有可能的边界标记
        boundaryStack.forEach(boundary => {
            // 移除普通边界标记（包括前后可能的空格）
            cleanedContent = cleanedContent.replace(new RegExp(`--${boundary}(?:\s*|\r\n|\n)`, 'gi'), '');
            // 移除结束边界标记（包括前后可能的空格）
            cleanedContent = cleanedContent.replace(new RegExp(`--${boundary}--(?:\s*|\r\n|\n)`, 'gi'), '');
            // 移除可能出现在内容中间的边界标记
            cleanedContent = cleanedContent.replace(new RegExp(`(?:\s|\r\n|\n)?--${boundary}(?:\s|\r\n|\n)?`, 'gi'), '');
            cleanedContent = cleanedContent.replace(new RegExp(`(?:\s|\r\n|\n)?--${boundary}--(?:\s|\r\n|\n)?`, 'gi'), '');
        });
        
        // 移除任何剩余的边界相关内容，包括特定的NextPart格式
        // 处理出现在内容中间或结尾的边界标记
        cleanedContent = cleanedContent.replace(/(?:\s|\r\n|\n)?--_.*?_=(?:\s|\r\n|\n)?/g, '');
        cleanedContent = cleanedContent.replace(/(?:\s|\r\n|\n)?--.*?--(?:\s|\r\n|\n)?/g, '');
        
        // 专门处理用户提到的特定NextPart格式边界标记
        // 移除出现在内容中的------=_001_NextPartXXX_=格式
        cleanedContent = cleanedContent.replace(/(?:\s|\r\n|\n)?------=_001_NextPart[0-9a-fA-F]+_=(?:\s|\r\n|\n)?/g, '');
        
        // 移除末尾可能的边界标记（不带前后空格）
        cleanedContent = cleanedContent.replace(/------=_001_NextPart[0-9a-fA-F]+_=$/g, '');
        cleanedContent = cleanedContent.replace(/--_.*?_=$/g, '');
        cleanedContent = cleanedContent.replace(/--.*?--$/g, '');
        
        // 对于base64编码的内容，保留换行符以确保解码正确
        // 检查内容是否看起来像base64编码
        const isBase64 = /^[A-Za-z0-9+/=\r\n]+$/.test(cleanedContent);
        
        if (isBase64) {
            // 仅移除开头和结尾的多余换行符
            cleanedContent = cleanedContent.replace(/^\s+/, '').replace(/\s+$/, '');
        } else {
            // 对于非base64内容，移除多余的空格和换行符
            cleanedContent = cleanedContent.replace(/\s+/g, ' ').trim();
        }
        
        return cleanedContent;
    }

    // 解析SMTP协议详情
    function parseSmtpDetails(messages) {
        let smtpDetails = {
            server: '',
            client: '',
            commands: [],
            responses: [],
            authentication: {
                method: '',
                success: false
            },
            mailFrom: '',
            rcptTo: [],
            hasData: false,
            dataContent: '',
            // 邮件头信息
            emailHeaders: {
                date: '',
                subject: '',
                mimeVersion: '',
                messageId: '',
                contentType: '',
                xPriority: '',
                xGuid: '',
                xHasAttach: '',
                mailer: '',
                from: '',
                to: ''
            },
            // 邮件内容
            emailContent: {
                plain: '',
                html: '',
                encoding: '',
                original: '',
                plainContentType: '',
                plainCharset: '',
                htmlContentType: '',
                htmlCharset: '',
                mimeParts: []
            },
            // 附件信息
            attachments: []
        };
        
        let isInDataSection = false;
        let dataContent = '';
        
        messages.forEach(msg => {
            const content = msg.raw || msg.info;
            
            // 处理消息内容，不依赖于方向标记
            const trimmedContent = content.trim();
            
            // 跳过空内容
            if (!trimmedContent) return;
            
            // 检查是否是服务器响应（以数字开头）
            const isServerResponse = /^\d{3} /.test(trimmedContent);
            
            if (!isServerResponse) {
                // 客户端命令（不以数字开头）或DATA内容
                const upperContent = trimmedContent.toUpperCase();
                
                // 检查是否是DATA结束标记（单独的点）
                if (isInDataSection && trimmedContent === '.') {
                    // DATA内容结束
                    isInDataSection = false;
                    return;
                }
                
                // 如果在DATA部分，收集所有内容
                if (isInDataSection) {
                    dataContent += content + '\n';
                    return;
                }
                
                // 否则处理客户端命令
                smtpDetails.client = msg.src || stream.srcIp;
                
                if (upperContent.startsWith('EHLO ')) {
                    smtpDetails.commands.push({ type: 'EHLO', content: content });
                } else if (upperContent.startsWith('MAIL FROM:')) {
                    smtpDetails.commands.push({ type: 'MAIL FROM', content: content });
                    // 提取发件人地址
                    const mailMatch = trimmedContent.match(/^MAIL FROM:(.+?)(?:\s+|$)/i);
                    if (mailMatch && mailMatch[1]) {
                        smtpDetails.mailFrom = mailMatch[1].trim();
                    }
                } else if (upperContent.startsWith('RCPT TO:')) {
                    smtpDetails.commands.push({ type: 'RCPT TO', content: content });
                    // 提取收件人地址
                    const rcptMatch = trimmedContent.match(/^RCPT TO:(.+?)(?:\s+|$)/i);
                    if (rcptMatch && rcptMatch[1]) {
                        const rcptValue = rcptMatch[1].trim();
                        smtpDetails.rcptTo.push(rcptValue);
                    }
                } else if (upperContent.startsWith('DATA')) {
                    smtpDetails.commands.push({ type: 'DATA', content: content });
                    smtpDetails.hasData = true;
                    isInDataSection = true;
                } else if (upperContent.startsWith('AUTH')) {
                    smtpDetails.commands.push({ type: 'AUTH', content: content });
                    smtpDetails.authentication.method = trimmedContent.split(' ')[1] || 'LOGIN';
                } else if (upperContent.startsWith('QUIT')) {
                    smtpDetails.commands.push({ type: 'QUIT', content: content });
                    isInDataSection = false;
                }
            } else {
                // 服务器响应（以数字开头）
                smtpDetails.server = msg.src || stream.dstIp;
                
                if (trimmedContent.startsWith('220 ')) {
                    smtpDetails.responses.push({ type: '220', content: content, description: '服务就绪' });
                } else if (trimmedContent.startsWith('250 ')) {
                    smtpDetails.responses.push({ type: '250', content: content, description: '请求被接受' });
                    if (trimmedContent.includes('235 2.7.0 Accepted')) {
                        smtpDetails.authentication.success = true;
                    }
                } else if (trimmedContent.startsWith('235 ')) {
                    smtpDetails.responses.push({ type: '235', content: content, description: '认证成功' });
                    smtpDetails.authentication.success = true;
                } else if (trimmedContent.startsWith('354 ')) {
                    smtpDetails.responses.push({ type: '354', content: content, description: '开始邮件输入' });
                    // 服务器确认DATA开始后，下一条消息就是DATA内容
                    isInDataSection = true;
                } else if (trimmedContent.startsWith('5')) {
                    smtpDetails.responses.push({ type: '5xx', content: content, description: '服务器错误' });
                }
            }
        });
        
        smtpDetails.dataContent = dataContent;
        
        // 解析DATA部分的邮件头和附件
        if (dataContent) {
            // 分割数据内容为行
            const lines = dataContent.split('\n');
            
            // 解析邮件头
            let inHeaders = true;
            let currentAttachment = null;
            let inAttachmentHeaders = false;
            let boundary = '';
            let inMultipart = false;
            let currentHeaderName = '';
            let currentHeaderValue = '';
            
            // 首先解析邮件头，获取multipart boundary
            for (const line of lines) {
                const trimmedLine = line.trim();
                
                if (inHeaders) {
                    if (!trimmedLine) {
                        // 空行表示邮件头结束
                        // 如果有未完成的头信息，处理它
                        if (currentHeaderName) {
                            switch (currentHeaderName.toLowerCase()) {
                                case 'content-type':
                                    smtpDetails.emailHeaders.contentType = currentHeaderValue;
                                    break;
                                // 其他头信息处理...
                            }
                            currentHeaderName = '';
                            currentHeaderValue = '';
                        }
                        inHeaders = false;
                        
                        // 检查是否是multipart邮件
                        const contentType = smtpDetails.emailHeaders.contentType;
                        if (contentType && contentType.includes('multipart/')) {
                            // 提取boundary
                            const boundaryMatch = contentType.match(/boundary="?([^";]+)"?/);
                            if (boundaryMatch && boundaryMatch[1]) {
                                boundary = boundaryMatch[1];
                                inMultipart = true;
                            }
                        }
                        continue;
                    }
                    
                    // 检查是否是新的头信息行还是续行
                    if (/^\s/.test(line)) {
                        // 续行，添加到当前头信息值
                        currentHeaderValue += ' ' + trimmedLine;
                    } else {
                        // 新的头信息
                        // 先处理之前的头信息
                        if (currentHeaderName) {
                            switch (currentHeaderName.toLowerCase()) {
                                case 'date':
                                    smtpDetails.emailHeaders.date = currentHeaderValue;
                                    break;
                                case 'subject':
                                    smtpDetails.emailHeaders.subject = currentHeaderValue;
                                    break;
                                case 'mime-version':
                                    smtpDetails.emailHeaders.mimeVersion = currentHeaderValue;
                                    break;
                                case 'message-id':
                                    smtpDetails.emailHeaders.messageId = currentHeaderValue;
                                    break;
                                case 'content-type':
                                    smtpDetails.emailHeaders.contentType = currentHeaderValue;
                                    break;
                                case 'x-priority':
                                    smtpDetails.emailHeaders.xPriority = currentHeaderValue;
                                    break;
                                case 'x-guid':
                                    smtpDetails.emailHeaders.xGuid = currentHeaderValue;
                                    break;
                                case 'x-has-attach':
                                    smtpDetails.emailHeaders.xHasAttach = currentHeaderValue;
                                    break;
                                case 'x-mailer':
                                    smtpDetails.emailHeaders.mailer = currentHeaderValue;
                                    break;
                                case 'from':
                                    smtpDetails.emailHeaders.from = currentHeaderValue;
                                    break;
                                case 'to':
                                    smtpDetails.emailHeaders.to = currentHeaderValue;
                                    break;
                            }
                        }
                        
                        // 解析新的头信息
                        const headerMatch = trimmedLine.match(/^([^:]+):\s*(.+)$/);
                        if (headerMatch) {
                            currentHeaderName = headerMatch[1];
                            currentHeaderValue = headerMatch[2].trim();
                        } else {
                            // 无法解析的头信息，重置
                            currentHeaderName = '';
                            currentHeaderValue = '';
                        }
                    }
                }
            }
            
            // 如果是multipart邮件，解析附件
            if (inMultipart && boundary) {
                // 重新遍历，解析附件
                let currentPartHeaders = {};
                let isInPart = false;
                let isInPartHeaders = false;
                let currentPartIsAttachment = false;
                let boundaryStack = [boundary]; // 处理嵌套multipart
                let currentBoundary = boundary;
                let currentPartHeaderName = '';
                let currentPartHeaderValue = '';
                let currentPartContent = '';
                
                lines.forEach(line => {
                    let lineContent = line;
                    
                    // 检查是否是当前boundary
                    const boundaryPattern = new RegExp(`^--${currentBoundary}`, 'i');
                    const endBoundaryPattern = new RegExp(`^--${currentBoundary}--`, 'i');
                    
                    if (endBoundaryPattern.test(lineContent)) {
                        // 边界结束标记
                        if (boundaryStack.length > 1) {
                            boundaryStack.pop();
                            currentBoundary = boundaryStack[boundaryStack.length - 1];
                        }
                        return;
                    }
                    
                    if (boundaryPattern.test(lineContent)) {
                        // 处理上一个part（如果存在）
                        if (Object.keys(currentPartHeaders).length > 0) {
                            // 创建附件对象
                            const attachment = {
                                name: '',
                                contentType: '',
                                charset: '',
                                contentTransferEncoding: '',
                                contentDisposition: '',
                                size: 0,
                                content: cleanAttachmentContent(currentPartContent, boundaryStack)
                            };
                            
                            // 填充附件信息
                            if (currentPartHeaders['content-type']) {
                                attachment.contentType = currentPartHeaders['content-type'];
                                // 提取charset
                                const charsetMatch = currentPartHeaders['content-type'].match(/charset="?([^";]+)"?/i);
                                if (charsetMatch && charsetMatch[1]) {
                                    attachment.charset = charsetMatch[1];
                                }
                                // 检查是否是嵌套的multipart
                                const nestedBoundaryMatch = currentPartHeaders['content-type'].match(/boundary="?([^";]+)"?/i);
                                if (nestedBoundaryMatch && nestedBoundaryMatch[1]) {
                                    // 处理嵌套的multipart
                                    boundaryStack.push(nestedBoundaryMatch[1]);
                                    currentBoundary = nestedBoundaryMatch[1];
                                }
                            }
                            if (currentPartHeaders['content-transfer-encoding']) {
                                attachment.contentTransferEncoding = currentPartHeaders['content-transfer-encoding'];
                            }
                            if (currentPartHeaders['content-disposition']) {
                                attachment.contentDisposition = currentPartHeaders['content-disposition'];
                                // 提取文件名
                                const filenameMatch = currentPartHeaders['content-disposition'].match(/filename="?([^";]+)"?/i);
                                if (filenameMatch && filenameMatch[1]) {
                                    attachment.name = filenameMatch[1];
                                }
                            }
                            
                            // 如果没有从content-disposition获取到文件名，尝试从content-type获取
                            if (!attachment.name && currentPartHeaders['content-type']) {
                                const nameMatch = currentPartHeaders['content-type'].match(/name="?([^";]+)"?/i);
                                if (nameMatch && nameMatch[1]) {
                                    attachment.name = nameMatch[1];
                                }
                            }
                            
                            // 标记为附件的条件：
                            // 1. 有文件名
                            // 或者 2. content-disposition包含attachment
                            // 或者 3. 不是text/plain或text/html且不是multipart/
                            // 检查是否是multipart类型
                            const isMultipart = currentPartHeaders['content-type'] && currentPartHeaders['content-type'].startsWith('multipart/');
                            
                            // 只有非multipart的part才作为附件或邮件内容处理
                            if (!isMultipart) {
                                // 标记为附件的条件：
                                // 1. 有文件名
                                // 或者 2. content-disposition包含attachment
                                // 或者 3. 不是text/plain或text/html
                                currentPartIsAttachment = !!(attachment.name || 
                                    (currentPartHeaders['content-disposition'] && currentPartHeaders['content-disposition'].includes('attachment')) ||
                                    (currentPartHeaders['content-type'] && !currentPartHeaders['content-type'].startsWith('text/plain') && !currentPartHeaders['content-type'].startsWith('text/html')));
                            } else {
                                // 如果是multipart类型，跳过处理，继续处理嵌套的part
                                // 重置状态，准备处理嵌套的multipart
                                currentPartHeaders = {};
                                currentPartContent = '';
                                isInPart = true;
                                isInPartHeaders = true;
                                currentPartIsAttachment = false;
                                return;
                            }
                            
                            if (currentPartIsAttachment) {
                                smtpDetails.attachments.push(attachment);
                            } else {
                                // 处理邮件正文内容
                                const contentType = currentPartHeaders['content-type'] || '';
                                const contentTransferEncoding = currentPartHeaders['content-transfer-encoding'] || '';
                                let content = cleanAttachmentContent(currentPartContent, boundaryStack);
                                
                                // 解码内容
                                if (contentTransferEncoding.toLowerCase() === 'base64') {
                                    try {
                                        content = atob(content);
                                    } catch (e) {
                                        console.error('Base64 decoding failed:', e);
                                    }
                                } else if (contentTransferEncoding.toLowerCase() === 'quoted-printable') {
                                    // 简单的quoted-printable解码
                                    content = content.replace(/=([0-9A-Fa-f]{2})/g, (match, hex) => {
                                        return String.fromCharCode(parseInt(hex, 16));
                                    }).replace(/=$/gm, '');
                                }
                                
                                // 提取纯文本内容
                                if (contentType.toLowerCase().includes('text/plain')) {
                                    smtpDetails.emailContent.plain = content;
                                } 
                                // 提取HTML内容
                                else if (contentType.toLowerCase().includes('text/html')) {
                                    smtpDetails.emailContent.html = content;
                                }
                            }
                        }
                        
                        // 重置状态
                        currentPartHeaders = {};
                        currentPartContent = '';
                        isInPart = true;
                        isInPartHeaders = true;
                        currentPartIsAttachment = false;
                        return;
                    }
                    
                    // 处理part内容
                    if (isInPart) {
                        if (isInPartHeaders) {
                            // 解析part头
                            const trimmedLine = line.trim();
                            
                            // 如果当前行是空行，但还没有解析到任何头信息，则跳过
                            if (!trimmedLine) {
                                // 只有当已经解析了至少一个头信息后，空行才表示part头结束
                                if (Object.keys(currentPartHeaders).length > 0) {
                                    // 保存当前未完成的头信息（如果有）
                                    if (currentPartHeaderName) {
                                        currentPartHeaders[currentPartHeaderName] = currentPartHeaderValue;
                                        currentPartHeaderName = '';
                                        currentPartHeaderValue = '';
                                    }
                                    isInPartHeaders = false;
                                }
                                return;
                            }
                            
                            // 检查是否是新的头信息行还是续行
                            if (/^\s/.test(line)) {
                                // 续行，添加到当前头信息值
                                if (currentPartHeaderName) {
                                    currentPartHeaderValue += ' ' + trimmedLine;
                                }
                            } else {
                                // 保存当前未完成的头信息
                                if (currentPartHeaderName) {
                                    currentPartHeaders[currentPartHeaderName] = currentPartHeaderValue;
                                }
                                
                                // 解析新的头信息
                                const headerMatch = trimmedLine.match(/^([^:]+):\s*(.+)$/);
                                if (headerMatch) {
                                    currentPartHeaderName = headerMatch[1].toLowerCase();
                                    currentPartHeaderValue = headerMatch[2].trim();
                                } else {
                                    currentPartHeaderName = '';
                                    currentPartHeaderValue = '';
                                }
                            }
                        } else {
                            // 收集part内容
                            currentPartContent += line + '\n';
                        }
                    }
                });
                
                // 保存最后一个未完成的头信息
                if (currentPartHeaderName) {
                    currentPartHeaders[currentPartHeaderName] = currentPartHeaderValue;
                    currentPartHeaderName = '';
                    currentPartHeaderValue = '';
                }
                
                // 处理最后一个part
                if (Object.keys(currentPartHeaders).length > 0) {
                    // 创建附件对象
                    const attachment = {
                        name: '',
                        contentType: '',
                        charset: '',
                        contentTransferEncoding: '',
                        contentDisposition: '',
                        size: 0,
                        content: cleanAttachmentContent(currentPartContent, boundaryStack)
                    };
                    
                    // 填充附件信息
                    if (currentPartHeaders['content-type']) {
                        attachment.contentType = currentPartHeaders['content-type'];
                        // 提取charset，处理各种格式
                        const charsetMatch = currentPartHeaders['content-type'].match(/charset\s*=\s*"?([^";\s]+)"?/i);
                        if (charsetMatch && charsetMatch[1]) {
                            attachment.charset = charsetMatch[1];
                        }
                    }
                    if (currentPartHeaders['content-transfer-encoding']) {
                        attachment.contentTransferEncoding = currentPartHeaders['content-transfer-encoding'];
                    }
                    if (currentPartHeaders['content-disposition']) {
                        attachment.contentDisposition = currentPartHeaders['content-disposition'];
                        // 提取文件名
                        const filenameMatch = currentPartHeaders['content-disposition'].match(/filename="?([^";]+)"?/i);
                        if (filenameMatch && filenameMatch[1]) {
                            attachment.name = filenameMatch[1];
                        }
                    }
                    
                    // 如果没有从content-disposition获取到文件名，尝试从content-type获取
                    if (!attachment.name && currentPartHeaders['content-type']) {
                        const nameMatch = currentPartHeaders['content-type'].match(/name="?([^";]+)"?/i);
                        if (nameMatch && nameMatch[1]) {
                            attachment.name = nameMatch[1];
                        }
                    }
                    
                    // 标记为附件的条件：
                    // 1. 有文件名
                    // 或者 2. content-disposition包含attachment
                    // 或者 3. 不是text/plain或text/html且不是multipart/
                    currentPartIsAttachment = !!(attachment.name || 
                        (currentPartHeaders['content-disposition'] && currentPartHeaders['content-disposition'].includes('attachment')) ||
                        (currentPartHeaders['content-type'] && !currentPartHeaders['content-type'].startsWith('text/plain') && !currentPartHeaders['content-type'].startsWith('text/html') && !currentPartHeaders['content-type'].startsWith('multipart/')));
                    
                    if (currentPartIsAttachment) {
                        smtpDetails.attachments.push(attachment);
                    } else {
                        // 处理邮件正文内容 - 只显示原文，不解码
                        const contentType = currentPartHeaders['content-type'] || '';
                        const contentTransferEncoding = currentPartHeaders['content-transfer-encoding'] || '';
                        let content = cleanAttachmentContent(currentPartContent, boundaryStack);
                        
                        // 提取charset，处理各种格式，包括换行和空格
                        const charsetMatch = contentType.match(/charset\s*=\s*"?([^";\s]+)"?/i);
                        const charset = charsetMatch ? charsetMatch[1] : '';
                        
                        // 保存编码规则
                        if (contentTransferEncoding) {
                            smtpDetails.emailContent.encoding = contentTransferEncoding;
                        }
                        
                        // 提取纯文本内容（原文）
                        if (contentType.toLowerCase().includes('text/plain')) {
                            smtpDetails.emailContent.plain = content;
                            smtpDetails.emailContent.original = content;
                            smtpDetails.emailContent.plainContentType = contentType;
                            smtpDetails.emailContent.plainCharset = charset;
                        } 
                        // 提取HTML内容（原文）
                        else if (contentType.toLowerCase().includes('text/html')) {
                            smtpDetails.emailContent.html = content;
                            if (!smtpDetails.emailContent.original) {
                                smtpDetails.emailContent.original = content;
                            }
                            smtpDetails.emailContent.htmlContentType = contentType;
                            smtpDetails.emailContent.htmlCharset = charset;
                        }
                    }
                }
            }
        }
        
        // 使用备用方法直接从流中提取附件信息，确保可靠性
        const fallbackAttachments = extractAttachmentsFromStream(messages);
        
        // 合并附件信息，避免重复
        fallbackAttachments.forEach(fallbackAttach => {
            const existing = smtpDetails.attachments.find(
                attach => attach.name === fallbackAttach.name
            );
            
            if (!existing) {
                // 将备用方法提取的附件添加到结果中
                smtpDetails.attachments.push({
                    name: fallbackAttach.name,
                    contentType: fallbackAttach.contentType || '',
                    contentTransferEncoding: fallbackAttach.contentTransferEncoding || '',
                    contentDisposition: fallbackAttach.contentDisposition || '',
                    charset: fallbackAttach.charset || '',
                    size: 0,
                    content: fallbackAttach.content || '',
                    detectedFrom: fallbackAttach.detectedFrom || 'fallback'
                });
            }
        });
        
        // 根据Content-Type数量提取所有内容部分的逻辑
        if (dataContent) {
            // 调试信息：打印dataContent的前2000字符
            console.log('SMTP DATA内容（前2000字符）:', dataContent.substring(0, 2000) + (dataContent.length > 2000 ? '...' : ''));
            
            // 首先提取所有Content-Type的位置和内容
            const contentTypeRegex = /Content-Type:\s*([^\n]+)/gi;
            const contentTypeMatches = [...dataContent.matchAll(contentTypeRegex)];
            
            console.log('提取到的Content-Type数量:', contentTypeMatches.length);
            contentTypeMatches.forEach((match, index) => {
                console.log(`Content-Type ${index + 1}:`, match[1]);
            });
            
            // 提取所有MIME部分
            const allMimeParts = [];
            
            // 1. 优化的multipart处理
            const mainContentType = dataContent.match(/Content-Type:\s*([^\n]+)/i);
            if (mainContentType && mainContentType[1] && mainContentType[1].includes('multipart/')) {
                // 提取所有边界
                const boundaryMatches = [...dataContent.matchAll(/boundary\s*=\s*"?([^";]+)"?/gi)];
                const boundaries = boundaryMatches.map(match => match[1]);
                
                if (boundaries.length > 0) {
                    // 使用最外层边界分割内容
                    const mainBoundary = boundaries[0];
                    const boundaryPattern = new RegExp(`--${mainBoundary}(?:--)?`, 'g');
                    const contentParts = dataContent.split(boundaryPattern);
                    
                    // 处理每个分割的部分
                    contentParts.forEach((part, partIndex) => {
                        // 跳过空部分和前后边界
                        if (!part.trim() || partIndex === 0 || partIndex === contentParts.length - 1) return;
                        
                        // 提取该部分的所有Content-Type
                        const partContentTypeMatches = [...part.matchAll(/Content-Type:\s*([^\n]+)/gi)];
                        
                        // 处理该部分的每个Content-Type
                        partContentTypeMatches.forEach((contentTypeMatch, index) => {
                            // 确定当前Content-Type的范围：从当前Content-Type开始到下一个Content-Type或部分结束
                            const currentContentTypeStart = contentTypeMatch.index;
                            const nextContentTypeMatch = partContentTypeMatches[index + 1];
                            const currentContentTypeEnd = nextContentTypeMatch ? nextContentTypeMatch.index : part.length;
                            const currentContentTypeRange = part.substring(currentContentTypeStart, currentContentTypeEnd);
                            
                            // 提取Content-Type，支持多行
                            let contentType = contentTypeMatch[1].trim();
                            // 检查当前Content-Type范围内是否有换行后的内容
                            const contentTypeLineEnd = contentTypeMatch.index + contentTypeMatch[0].length;
                            const remainingRange = currentContentTypeRange.substring(contentTypeLineEnd);
                            const continuationMatch = remainingRange.match(/^(?:\r?\n\s+([^\n]+))+/);
                            if (continuationMatch) {
                                // 合并多行的Content-Type
                                contentType += ' ' + continuationMatch[0].replace(/\r?\n\s*/g, ' ').trim();
                            }
                            
                            // 提取charset，支持各种格式：charset="GB2312", charset=GB2312, charset='UTF-8', 以及换行情况
                            let charset = '';
                            // 先从Content-Type行本身提取
                            let charsetMatch = contentType.match(/charset\s*=\s*(?:"|')?([^"';\s]+)(?:"|')?/i);
                            if (charsetMatch) {
                                charset = charsetMatch[1];
                            } else {
                                // 检查当前Content-Type范围内是否有换行后的charset
                                const extendedCharsetMatch = currentContentTypeRange.match(/charset\s*=\s*(?:"|')?([^"';\s]+)(?:"|')?/i);
                                if (extendedCharsetMatch) {
                                    charset = extendedCharsetMatch[1];
                                }
                            }
                            
                            // 提取Content-Transfer-Encoding，只在当前Content-Type范围内查找
                            const encodingMatch = currentContentTypeRange.match(/Content-Transfer-Encoding:\s*([^\n]+)/i);
                            const contentTransferEncoding = encodingMatch ? encodingMatch[1].trim() : '';
                            
                            // 提取Content-Disposition，只在当前Content-Type范围内查找，支持多行
                            const dispositionMatch = currentContentTypeRange.match(/Content-Disposition:\s*([\s\S]*?)(?=\r?\n(?:Content-|$))/i);
                            let contentDisposition = dispositionMatch ? dispositionMatch[1].trim() : '';
                            // 合并多行的Content-Disposition
                            contentDisposition = contentDisposition.replace(/\r?\n\s*/g, ' ');
                            
                            // 提取该Content-Type对应的内容
                            let content = '';
                            
                            // 首先找到所有头信息结束的位置（连续两个换行符）
                            // 头信息结束后才是真正的内容
                            const headersEndMatch = currentContentTypeRange.match(/\r?\n\r?\n([\s\S]*)/);
                            if (headersEndMatch) {
                                // 提取头信息后的内容
                                content = headersEndMatch[1].trim();
                            } else {
                                // 如果没有找到连续两个换行符，尝试查找所有头信息后的内容
                                // 移除所有头信息行，剩下的就是内容
                                content = currentContentTypeRange.replace(/^(?:Content-(?:Type|Transfer-Encoding|Disposition|ID):[^\n]+\r?\n)*\s*/i, '').trim();
                            }
                            
                            // 清理内容，移除任何边界标记和特殊字符
                            content = cleanAttachmentContent(content, boundaries);
                            
                            // 判断部分类型
                            let partType = '其他';
                            if (contentType.toLowerCase().includes('text/plain')) {
                                partType = '纯文本';
                                smtpDetails.emailContent.plain = content;
                                smtpDetails.emailContent.original = content;
                                smtpDetails.emailContent.plainContentType = contentType;
                                smtpDetails.emailContent.plainCharset = charset;
                                if (contentTransferEncoding) {
                                    smtpDetails.emailContent.encoding = contentTransferEncoding;
                                }
                            } else if (contentType.toLowerCase().includes('text/html')) {
                                partType = 'HTML';
                                smtpDetails.emailContent.html = content;
                                if (!smtpDetails.emailContent.original) {
                                    smtpDetails.emailContent.original = content;
                                }
                                smtpDetails.emailContent.htmlContentType = contentType;
                                smtpDetails.emailContent.htmlCharset = charset;
                                if (contentTransferEncoding) {
                                    smtpDetails.emailContent.encoding = contentTransferEncoding;
                                }
                            } else if (contentDisposition.toLowerCase().includes('attachment') || contentType.toLowerCase().includes('application/')) {
                                partType = '附件';
                            } else if (contentType.toLowerCase().includes('multipart/')) {
                                partType = 'Multipart容器';
                            }
                            
                            // 提取文件名，与附件处理逻辑一致
                            let filename = '';
                            // 1. 从Content-Disposition中提取filename
                            if (contentDisposition) {
                                const filenameMatch = contentDisposition.match(/filename="?([^";]+)"?/i);
                                if (filenameMatch && filenameMatch[1]) {
                                    filename = filenameMatch[1];
                                }
                            }
                            // 2. 如果没有从Content-Disposition获取到文件名，尝试从Content-Type获取
                            if (!filename && contentType) {
                                const nameMatch = contentType.match(/name="?([^";]+)"?/i);
                                if (nameMatch && nameMatch[1]) {
                                    filename = nameMatch[1];
                                }
                            }
                            
                            // 添加到parts数组
                            allMimeParts.push({
                                type: partType,
                                filename,
                                contentType,
                                charset,
                                contentTransferEncoding,
                                contentDisposition,
                                content: content
                            });
                        });
                    });
                }
            }
            
            // 2. 直接提取所有Content-Type，确保不遗漏任何部分
            contentTypeMatches.forEach((contentTypeMatch, index) => {
                // 确定当前Content-Type的范围：从当前Content-Type开始到下一个Content-Type或数据结束
                const currentContentTypeStart = contentTypeMatch.index;
                const nextContentTypeMatch = contentTypeMatches[index + 1];
                const currentContentTypeEnd = nextContentTypeMatch ? nextContentTypeMatch.index : dataContent.length;
                const currentContentTypeRange = dataContent.substring(currentContentTypeStart, currentContentTypeEnd);
                
                // 提取Content-Type，支持多行
                let contentType = contentTypeMatch[1].trim();
                // 检查当前Content-Type范围内是否有换行后的内容
                const contentTypeLineEnd = contentTypeMatch.index + contentTypeMatch[0].length;
                const remainingRange = currentContentTypeRange.substring(contentTypeLineEnd);
                const continuationMatch = remainingRange.match(/^(?:\r?\n\s+([^\n]+))+/);
                if (continuationMatch) {
                    // 合并多行的Content-Type
                    contentType += ' ' + continuationMatch[0].replace(/\r?\n\s*/g, ' ').trim();
                }
                
                // 检查是否已经添加过
                const alreadyExists = allMimeParts.some(part => 
                    part.contentType === contentType
                );
                
                if (alreadyExists) return;
                
                // 提取charset，支持各种格式：charset="GB2312", charset=GB2312, charset='UTF-8', 以及换行情况
                let charset = '';
                // 先从Content-Type行本身提取
                let charsetMatch = contentType.match(/charset\s*=\s*(?:"|')?([^"';\s]+)(?:"|')?/i);
                if (charsetMatch) {
                    charset = charsetMatch[1];
                } else {
                    // 检查当前Content-Type范围内是否有换行后的charset
                    const extendedCharsetMatch = currentContentTypeRange.match(/charset\s*=\s*(?:"|')?([^"';\s]+)(?:"|')?/i);
                    if (extendedCharsetMatch) {
                        charset = extendedCharsetMatch[1];
                    }
                }
                
                // 提取Content-Transfer-Encoding，只在当前Content-Type范围内查找
                const encodingMatch = currentContentTypeRange.match(/Content-Transfer-Encoding:\s*([^\n]+)/i);
                const contentTransferEncoding = encodingMatch ? encodingMatch[1].trim() : '';
                
                // 提取Content-Disposition，只在当前Content-Type范围内查找，支持多行
                const dispositionMatch = currentContentTypeRange.match(/Content-Disposition:\s*([\s\S]*?)(?=\r?\n(?:Content-|$))/i);
                let contentDisposition = dispositionMatch ? dispositionMatch[1].trim() : '';
                // 合并多行的Content-Disposition
                contentDisposition = contentDisposition.replace(/\r?\n\s*/g, ' ');
                
                // 提取内容
                let content = '';
                
                // 首先找到所有头信息结束的位置（连续两个换行符）
                // 头信息结束后才是真正的内容
                const headersEndMatch = currentContentTypeRange.match(/\r?\n\r?\n([\s\S]*)/);
                if (headersEndMatch) {
                    // 提取头信息后的内容
                    content = headersEndMatch[1].trim();
                } else {
                    // 如果没有找到连续两个换行符，尝试查找所有头信息后的内容
                    // 移除所有头信息行，剩下的就是内容
                    content = currentContentTypeRange.replace(/^(?:Content-(?:Type|Transfer-Encoding|Disposition|ID):[^\n]+\r?\n)*\s*/i, '').trim();
                }
                
                // 清理内容
                content = cleanAttachmentContent(content, []);
                
                // 判断部分类型
                let partType = '其他';
                if (contentType.toLowerCase().includes('text/plain')) {
                    partType = '纯文本';
                    smtpDetails.emailContent.plain = content;
                    smtpDetails.emailContent.original = content;
                    smtpDetails.emailContent.plainContentType = contentType;
                    smtpDetails.emailContent.plainCharset = charset;
                    if (contentTransferEncoding) {
                        smtpDetails.emailContent.encoding = contentTransferEncoding;
                    }
                } else if (contentType.toLowerCase().includes('text/html')) {
                    partType = 'HTML';
                    smtpDetails.emailContent.html = content;
                    if (!smtpDetails.emailContent.original) {
                        smtpDetails.emailContent.original = content;
                    }
                    smtpDetails.emailContent.htmlContentType = contentType;
                    smtpDetails.emailContent.htmlCharset = charset;
                    if (contentTransferEncoding) {
                        smtpDetails.emailContent.encoding = contentTransferEncoding;
                    }
                } else if (contentDisposition.toLowerCase().includes('attachment') || contentType.toLowerCase().includes('application/')) {
                    partType = '附件';
                } else if (contentType.toLowerCase().includes('multipart/')) {
                    partType = 'Multipart容器';
                }
                
                // 提取文件名，与附件处理逻辑一致
                let filename = '';
                // 1. 从Content-Disposition中提取filename
                if (contentDisposition) {
                    const filenameMatch = contentDisposition.match(/filename="?([^";]+)"?/i);
                    if (filenameMatch && filenameMatch[1]) {
                        filename = filenameMatch[1];
                    }
                }
                // 2. 如果没有从Content-Disposition获取到文件名，尝试从Content-Type获取
                if (!filename && contentType) {
                    const nameMatch = contentType.match(/name="?([^";]+)"?/i);
                    if (nameMatch && nameMatch[1]) {
                        filename = nameMatch[1];
                    }
                }
                            
                            // 添加到parts数组
                            allMimeParts.push({
                                type: partType,
                                filename,
                                contentType,
                                charset,
                                contentTransferEncoding,
                                contentDisposition,
                                content: content
                            });
            });
            
            // 3. 确保所有Content-Type都被提取到
            if (allMimeParts.length < contentTypeMatches.length) {
                // 直接添加所有Content-Type
                contentTypeMatches.forEach((contentTypeMatch, index) => {
                    const contentType = contentTypeMatch[1].trim();
                    const alreadyExists = allMimeParts.some(part => 
                        part.contentType === contentType
                    );
                    
                    if (!alreadyExists) {
                        // 尝试提取文件名
                        let filename = '';
                        // 从Content-Type中提取name
                        const nameMatch = contentType.match(/name\s*=\s*(?:"|')?([^"';\s]+)(?:"|')?/i);
                        if (nameMatch) {
                            filename = nameMatch[1];
                        }
                        
                        allMimeParts.push({
                            type: '其他',
                            filename,
                            contentType: contentType,
                            charset: '',
                            contentTransferEncoding: '',
                            contentDisposition: '',
                            content: ''
                        });
                    }
                });
            }
            
            // 保存所有MIME部分
            smtpDetails.emailContent.mimeParts = allMimeParts;
        }
        
        return smtpDetails;
}

// 解析HTTP对话详情
function parseHttpDetails(messages) {
    let httpDetails = {
        requests: [],
        responses: [],
        sessions: [],
        // 统计信息
        stats: {
            totalRequests: 0,
            totalResponses: 0,
            successfulResponses: 0,
            redirectResponses: 0,
            errorResponses: 0,
            avgResponseTime: 0
        }
    };
    
    // 按请求分组响应
    let pendingRequests = [];
    let requestResponsePairs = [];
    
    // 用于处理分块响应的状态变量
    let currentResponse = null;
    let currentResponseDirection = null;
    
    messages.forEach((msg, index) => {
        const content = msg.raw || msg.info;
        const isRequest = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+/.test(content);
        const isResponse = /^HTTP\/\d+\.\d+\s+\d+/.test(content);
        
        // 检查是否是当前响应的延续（同一方向，没有新的请求/响应开始）
        const isContinuation = !isRequest && !isResponse && currentResponse !== null && msg.direction === currentResponseDirection;
        
        if (isRequest) {
            // 这是一个新请求，结束任何当前的响应处理
            if (currentResponse) {
                // 保存当前的响应
                httpDetails.responses.push(currentResponse);
                
                // 匹配最近的请求
                if (pendingRequests.length > 0) {
                    const request = pendingRequests[pendingRequests.length - 1];
                    requestResponsePairs.push({
                        request: request,
                        response: currentResponse,
                        responseTime: currentResponse.timestamp - request.timestamp
                    });
                    pendingRequests.pop();
                }
                currentResponse = null;
            }
            
            // 解析HTTP请求
            const requestMatch = content.match(/^(\w+)\s+([^\s]+)\s+HTTP\/(\d+\.\d+)/);
            if (requestMatch) {
                const request = {
                    method: requestMatch[1],
                    path: requestMatch[2],
                    version: requestMatch[3],
                    headers: {},
                    body: '',
                    timestamp: msg.timestamp,
                    messageId: msg.uniqueId,
                    direction: msg.direction
                };
                
                // 解析头部
                const headerLines = content.split(/\r?\n/);
                for (let i = 1; i < headerLines.length; i++) {
                    const line = headerLines[i].trim();
                    if (!line) {
                        break;
                    }
                    const colonIndex = line.indexOf(':');
                    if (colonIndex > 0) {
                        const name = line.substring(0, colonIndex).trim();
                        const value = line.substring(colonIndex + 1).trim();
                        request.headers[name] = value;
                    }
                }
                
                // 提取请求体
                const headerEndBoundary = '\r\n\r\n';
                const headerEndPos = content.indexOf(headerEndBoundary);
                
                if (headerEndPos !== -1) {
                    request.body = content.substring(headerEndPos + headerEndBoundary.length);
                }
                
                httpDetails.requests.push(request);
                pendingRequests.push(request);
            }
        } else if (isResponse) {
            // 这是一个新响应，结束任何当前的响应处理
            if (currentResponse) {
                httpDetails.responses.push(currentResponse);
                
                // 匹配最近的请求
                if (pendingRequests.length > 0) {
                    const request = pendingRequests[pendingRequests.length - 1];
                    requestResponsePairs.push({
                        request: request,
                        response: currentResponse,
                        responseTime: currentResponse.timestamp - request.timestamp
                    });
                    pendingRequests.pop();
                }
            }
            
            // 解析HTTP响应
            const responseMatch = content.match(/^HTTP\/(\d+\.\d+)\s+(\d+)\s+(.+)/);
            if (responseMatch) {
                currentResponse = {
                    version: responseMatch[1],
                    statusCode: parseInt(responseMatch[2]),
                    statusText: responseMatch[3],
                    headers: {},
                    body: '',
                    timestamp: msg.timestamp,
                    messageId: msg.uniqueId,
                    direction: msg.direction
                };
                currentResponseDirection = msg.direction;
                
                // 解析头部
                const headerLines = content.split(/\r?\n/);
                for (let i = 1; i < headerLines.length; i++) {
                    const line = headerLines[i].trim();
                    if (!line) {
                        break;
                    }
                    const colonIndex = line.indexOf(':');
                    if (colonIndex > 0) {
                        const name = line.substring(0, colonIndex).trim();
                        const value = line.substring(colonIndex + 1).trim();
                        currentResponse.headers[name] = value;
                    }
                }
                
                // 提取初始响应体
                const headerEndBoundary = '\r\n\r\n';
                const headerEndPos = content.indexOf(headerEndBoundary);
                
                if (headerEndPos !== -1) {
                    currentResponse.body = content.substring(headerEndPos + headerEndBoundary.length);
                }
            }
        } else if (isContinuation) {
            // 这是当前响应的延续，将内容追加到响应体
            currentResponse.body += content;
        }
    });
    
    // 处理最后一个响应
    if (currentResponse) {
        httpDetails.responses.push(currentResponse);
        
        // 匹配最近的请求
        if (pendingRequests.length > 0) {
            const request = pendingRequests[pendingRequests.length - 1];
            requestResponsePairs.push({
                request: request,
                response: currentResponse,
                responseTime: currentResponse.timestamp - request.timestamp
            });
            pendingRequests.pop();
        }
    };
    
    // 计算统计信息
    httpDetails.stats.totalRequests = httpDetails.requests.length;
    httpDetails.stats.totalResponses = httpDetails.responses.length;
    httpDetails.stats.successfulResponses = httpDetails.responses.filter(r => r.statusCode >= 200 && r.statusCode < 300).length;
    httpDetails.stats.redirectResponses = httpDetails.responses.filter(r => r.statusCode >= 300 && r.statusCode < 400).length;
    httpDetails.stats.errorResponses = httpDetails.responses.filter(r => r.statusCode >= 400).length;
    
    // 计算平均响应时间
    if (requestResponsePairs.length > 0) {
        const totalResponseTime = requestResponsePairs.reduce((sum, pair) => sum + pair.responseTime, 0);
        httpDetails.stats.avgResponseTime = totalResponseTime / requestResponsePairs.length;
    }
    
    httpDetails.sessions = requestResponsePairs;
    
    return httpDetails;
}

// 生成HTTP详情HTML
function generateHttpDetailsHtml(httpDetails) {
    return `
        <div style="margin-top: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 8px; border-left: 4px solid #3498db;">
            <h4 style="margin-bottom: 15px; color: #2c3e50; font-size: 14px;">HTTP协议详情</h4>
            
            <!-- 统计信息 -->
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px;">
                <div style="padding: 10px; background-color: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">
                    <div style="font-weight: bold; color: #3498db; margin-bottom: 5px;">总请求数</div>
                    <div style="color: #333;">${httpDetails.stats.totalRequests}</div>
                </div>
                <div style="padding: 10px; background-color: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">
                    <div style="font-weight: bold; color: #3498db; margin-bottom: 5px;">总响应数</div>
                    <div style="color: #333;">${httpDetails.stats.totalResponses}</div>
                </div>
                <div style="padding: 10px; background-color: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">
                    <div style="font-weight: bold; color: #3498db; margin-bottom: 5px;">成功响应</div>
                    <div style="color: #27ae60;">${httpDetails.stats.successfulResponses}</div>
                </div>
                <div style="padding: 10px; background-color: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">
                    <div style="font-weight: bold; color: #3498db; margin-bottom: 5px;">重定向响应</div>
                    <div style="color: #f39c12;">${httpDetails.stats.redirectResponses}</div>
                </div>
                <div style="padding: 10px; background-color: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">
                    <div style="font-weight: bold; color: #3498db; margin-bottom: 5px;">错误响应</div>
                    <div style="color: #e74c3c;">${httpDetails.stats.errorResponses}</div>
                </div>
                <div style="padding: 10px; background-color: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">
                    <div style="font-weight: bold; color: #3498db; margin-bottom: 5px;">平均响应时间</div>
                    <div style="color: #333;">${httpDetails.stats.avgResponseTime.toFixed(3)}s</div>
                </div>
            </div>
            
            <!-- 请求响应会话列表 -->
            <div style="margin-bottom: 15px; padding: 15px; background-color: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">
                <div style="font-weight: bold; color: #3498db; margin-bottom: 10px;">请求响应会话</div>
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background-color: #f5f5f5;">
                            <th style="padding: 10px; border: 1px solid #ddd; text-align: left; font-size: 12px;">序号</th>
                            <th style="padding: 10px; border: 1px solid #ddd; text-align: left; font-size: 12px;">请求方法</th>
                            <th style="padding: 10px; border: 1px solid #ddd; text-align: left; font-size: 12px;">请求路径</th>
                            <th style="padding: 10px; border: 1px solid #ddd; text-align: left; font-size: 12px;">请求体</th>
                            <th style="padding: 10px; border: 1px solid #ddd; text-align: left; font-size: 12px;">响应状态</th>
                            <th style="padding: 10px; border: 1px solid #ddd; text-align: left; font-size: 12px;">响应时间</th>
                            <th style="padding: 10px; border: 1px solid #ddd; text-align: left; font-size: 12px;">内容类型</th>
                            <th style="padding: 10px; border: 1px solid #ddd; text-align: left; font-size: 12px;">内容长度</th>
                            <th style="padding: 10px; border: 1px solid #ddd; text-align: left; font-size: 12px;">响应内容</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${httpDetails.sessions.map((session, index) => {
                            const statusClass = session.response.statusCode >= 200 && session.response.statusCode < 300 ? 'success' : 
                                             session.response.statusCode >= 300 && session.response.statusCode < 400 ? 'redirect' : 'error';
                            const contentType = session.response.headers['Content-Type'] || '-';
                            const contentLength = session.response.headers['Content-Length'] || session.response.body.length;
                            
                            // 显示原始响应数据，支持完整复制
                            let responseContent = session.response.body || '';
                            let contentPreview = responseContent; // 保持完整内容，让CSS处理视觉截断
                            
                            // 显示原始请求数据，支持完整复制
                            let requestBody = session.request.body || '';
                            
                            return `
                                <tr>
                                    <td style="padding: 10px; border: 1px solid #ddd; font-size: 12px;">${index + 1}</td>
                                    <td style="padding: 10px; border: 1px solid #ddd; font-size: 12px; font-weight: bold;">${session.request.method}</td>
                                    <td style="padding: 10px; border: 1px solid #ddd; font-size: 12px; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${htmlEscape(session.request.path)}</td>
                                    <td style="padding: 10px; border: 1px solid #ddd; font-size: 12px; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: help;" title="${htmlEscape(requestBody)}" data-full-content="${htmlEscape(requestBody)}">${htmlEscape(requestBody)}</td>
                                    <td style="padding: 10px; border: 1px solid #ddd; font-size: 12px; color: ${statusClass === 'success' ? '#27ae60' : statusClass === 'redirect' ? '#f39c12' : '#e74c3c'};">${session.response.statusCode} ${session.response.statusText}</td>
                                    <td style="padding: 10px; border: 1px solid #ddd; font-size: 12px;">${session.responseTime.toFixed(3)}s</td>
                                    <td style="padding: 10px; border: 1px solid #ddd; font-size: 12px; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${contentType}</td>
                                    <td style="padding: 10px; border: 1px solid #ddd; font-size: 12px; text-align: right;">${contentLength} bytes</td>
                                    <td style="padding: 10px; border: 1px solid #ddd; font-size: 12px; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: help;" title="${htmlEscape(responseContent)}" data-full-content="${htmlEscape(responseContent)}">${htmlEscape(responseContent)}</td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>
            
            <!-- 请求响应详情 -->
            <div style="padding: 15px; background-color: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">
                <div style="font-weight: bold; color: #3498db; margin-bottom: 10px;">请求响应详情</div>
                ${httpDetails.sessions.map((session, index) => {
                    const request = session.request;
                    const response = session.response;
                    const statusClass = response.statusCode >= 200 && response.statusCode < 300 ? '#27ae60' : 
                                     response.statusCode >= 300 && response.statusCode < 400 ? '#f39c12' : '#e74c3c';
                    
                    return `
                        <div style="margin-bottom: 25px; padding: 15px; border: 1px solid #e0e0e0; border-radius: 8px; background-color: #fafafa;">
                            <div style="font-weight: bold; font-size: 14px; margin-bottom: 15px; color: #333;">请求响应会话 ${index + 1}</div>
                            
                            <!-- 请求部分 -->
                            <div style="margin-bottom: 15px; padding: 12px; border-left: 3px solid #3498db; background-color: #f0f8ff; border-radius: 4px;">
                                <div style="font-weight: bold; font-size: 13px; margin-bottom: 5px;">请求: ${request.method} ${htmlEscape(request.path)}</div>
                                <div style="margin-bottom: 5px; font-size: 12px;">
                                    <strong>版本:</strong> ${request.version} | 
                                    <strong>时间:</strong> ${new Date(request.timestamp * 1000).toLocaleString()}
                                </div>
                                ${Object.keys(request.headers).length > 0 ? `
                                    <div style="margin: 5px 0;">
                                        <div style="font-weight: 500; font-size: 12px; color: #666; margin-bottom: 3px;">头部信息:</div>
                                        <table style="width: 100%; border-collapse: collapse; font-size: 11px;">
                                            <tbody>
                                                ${Object.entries(request.headers).map(([key, value]) => `
                                                    <tr>
                                                        <td style="padding: 2px 5px; border-bottom: 1px solid #eee; font-weight: bold; color: #333; width: 150px;">${key}:</td>
                                                        <td style="padding: 2px 5px; border-bottom: 1px solid #eee; color: #666;">${htmlEscape(value)}</td>
                                                    </tr>
                                                `).join('')}
                                            </tbody>
                                        </table>
                                    </div>
                                ` : ''}
                                ${request.body ? `
                                    <div style="margin: 5px 0;">
                                        <div style="font-weight: 500; font-size: 12px; color: #666; margin-bottom: 3px;">请求体:</div>
                                        <div style="padding: 5px; background-color: #fff; border: 1px solid #eee; border-radius: 3px; font-family: 'Courier New', monospace; font-size: 11px; max-height: 100px; overflow-y: auto;">${htmlEscape(request.body)}</div>
                                    </div>
                                ` : ''}
                            </div>
                            
                            <!-- 响应部分 -->
                            <div style="padding: 12px; border-left: 3px solid ${statusClass}; background-color: #f8fff8; border-radius: 4px;">
                                <div style="font-weight: bold; font-size: 13px; margin-bottom: 5px;">响应: ${response.statusCode} ${response.statusText}</div>
                                <div style="margin-bottom: 5px; font-size: 12px;">
                                    <strong>版本:</strong> ${response.version} | 
                                    <strong>时间:</strong> ${new Date(response.timestamp * 1000).toLocaleString()} |
                                    <strong>响应时间:</strong> ${session.responseTime.toFixed(3)}s
                                </div>
                                ${Object.keys(response.headers).length > 0 ? `
                                    <div style="margin: 5px 0;">
                                        <div style="font-weight: 500; font-size: 12px; color: #666; margin-bottom: 3px;">头部信息:</div>
                                        <table style="width: 100%; border-collapse: collapse; font-size: 11px;">
                                            <tbody>
                                                ${Object.entries(response.headers).map(([key, value]) => `
                                                    <tr>
                                                        <td style="padding: 2px 5px; border-bottom: 1px solid #eee; font-weight: bold; color: #333; width: 150px;">${key}:</td>
                                                        <td style="padding: 2px 5px; border-bottom: 1px solid #eee; color: #666;">${htmlEscape(value)}</td>
                                                    </tr>
                                                `).join('')}
                                            </tbody>
                                        </table>
                                    </div>
                                ` : ''}
                                ${response.body ? `
                                    <div style="margin: 5px 0;">
                                        <div style="font-weight: 500; font-size: 12px; color: #666; margin-bottom: 3px;">响应体:</div>
                                        <div style="padding: 5px; background-color: #fff; border: 1px solid #eee; border-radius: 3px; font-family: 'Courier New', monospace; font-size: 11px; max-height: 100px; overflow-y: auto;">${htmlEscape(response.body)}</div>
                                    </div>
                                ` : ''}
                            </div>
                        </div>
                    `;
                }).join('')}
            </div>
        </div>
    `;
}

// 生成SMTP详情HTML
function generateSmtpDetailsHtml(smtpDetails) {
        return `
            <div style="margin-top: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 8px; border-left: 4px solid #3498db;">
                <h4 style="margin-bottom: 15px; color: #2c3e50; font-size: 14px;">SMTP协议详情</h4>
                
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px;">
                    <div style="padding: 10px; background-color: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">
                        <div style="font-weight: bold; color: #3498db; margin-bottom: 5px;">客户端</div>
                        <div style="color: #666;">${smtpDetails.client}</div>
                    </div>
                    <div style="padding: 10px; background-color: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">
                        <div style="font-weight: bold; color: #3498db; margin-bottom: 5px;">服务器</div>
                        <div style="color: #666;">${smtpDetails.server}</div>
                    </div>
                    <div style="padding: 10px; background-color: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">
                        <div style="font-weight: bold; color: #3498db; margin-bottom: 5px;">认证方式</div>
                        <div style="color: #666;">${smtpDetails.authentication.method}</div>
                    </div>
                    <div style="padding: 10px; background-color: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">
                        <div style="font-weight: bold; color: #3498db; margin-bottom: 5px;">认证状态</div>
                        <div style="color: ${smtpDetails.authentication.success ? '#27ae60' : '#e74c3c'};">${smtpDetails.authentication.success ? '成功' : '失败'}</div>
                    </div>
                </div>
                
                <!-- 发件人和收件人信息已合并到邮件头信息中，此处隐藏 -->
                
                <!-- 邮件头信息 -->
                <div style="margin-bottom: 15px; padding: 15px; background-color: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">
                    <div style="font-weight: bold; color: #3498db; margin-bottom: 10px;">邮件头信息</div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px;">
                        ${smtpDetails.emailHeaders.date ? `
                            <div>
                                <div style="font-weight: 500; color: #666; font-size: 12px;">发送时间</div>
                                <div style="color: #333;">${htmlEscape(smtpDetails.emailHeaders.date)}</div>
                            </div>
                        ` : ''}
                        ${smtpDetails.emailHeaders.subject ? `
                            <div>
                                <div style="font-weight: 500; color: #666; font-size: 12px;">主题</div>
                                <div style="color: #333;">${htmlEscape(smtpDetails.emailHeaders.subject)}</div>
                            </div>
                        ` : ''}
                        ${smtpDetails.emailHeaders.mimeVersion ? `
                            <div>
                                <div style="font-weight: 500; color: #666; font-size: 12px;">MIME版本</div>
                                <div style="color: #333;">${htmlEscape(smtpDetails.emailHeaders.mimeVersion)}</div>
                            </div>
                        ` : ''}
                        ${smtpDetails.emailHeaders.mailer ? `
                            <div>
                                <div style="font-weight: 500; color: #666; font-size: 12px;">邮件客户端</div>
                                <div style="color: #333;">${htmlEscape(smtpDetails.emailHeaders.mailer)}</div>
                            </div>
                        ` : ''}
                        ${smtpDetails.emailHeaders.messageId ? `
                            <div>
                                <div style="font-weight: 500; color: #666; font-size: 12px;">消息ID</div>
                                <div style="color: #333; font-size: 12px; word-break: break-all;">${htmlEscape(smtpDetails.emailHeaders.messageId)}</div>
                            </div>
                        ` : ''}
                        ${smtpDetails.emailHeaders.contentType ? `
                            <div>
                                <div style="font-weight: 500; color: #666; font-size: 12px;">内容类型</div>
                                <div style="color: #333; font-size: 12px;">${htmlEscape(smtpDetails.emailHeaders.contentType)}</div>
                            </div>
                        ` : ''}
                        ${smtpDetails.emailHeaders.xPriority ? `
                            <div>
                                <div style="font-weight: 500; color: #666; font-size: 12px;">优先级</div>
                                <div style="color: #333;">${htmlEscape(smtpDetails.emailHeaders.xPriority)}</div>
                            </div>
                        ` : ''}
                        ${smtpDetails.emailHeaders.xHasAttach ? `
                            <div>
                                <div style="font-weight: 500; color: #666; font-size: 12px;">是否有附件</div>
                                <div style="color: ${smtpDetails.emailHeaders.xHasAttach.toLowerCase() === 'yes' ? '#27ae60' : '#666'};">${htmlEscape(smtpDetails.emailHeaders.xHasAttach)}</div>
                            </div>
                        ` : ''}
                        ${smtpDetails.emailHeaders.from ? `
                            <div>
                                <div style="font-weight: 500; color: #666; font-size: 12px;">邮件发件人</div>
                                <div style="color: #333;">${htmlEscape(smtpDetails.emailHeaders.from)}</div>
                            </div>
                        ` : ''}
                        ${smtpDetails.emailHeaders.to ? `
                            <div>
                                <div style="font-weight: 500; color: #666; font-size: 12px;">邮件收件人</div>
                                <div style="color: #333;">${htmlEscape(smtpDetails.emailHeaders.to)}</div>
                            </div>
                        ` : ''}
                    </div>
                </div>
                
                <!-- 邮件内容 -->
                <div style="margin-bottom: 15px; padding: 15px; background-color: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">
                    <div style="font-weight: bold; color: #3498db; margin-bottom: 15px;">邮件内容</div>
                    ${(smtpDetails.emailContent.plain || smtpDetails.emailContent.html || (smtpDetails.emailContent.mimeParts && smtpDetails.emailContent.mimeParts.length > 0)) ? `

                        
                        <!-- MIME部分表格 -->
                        ${smtpDetails.emailContent.mimeParts && smtpDetails.emailContent.mimeParts.length > 0 ? `
                            <div>
                                <div style="font-weight: 500; color: #666; font-size: 13px; margin-bottom: 15px;">MIME部分详情</div>
                                <div style="overflow-x: auto;">
                                    <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                                        <thead>
                                            <tr style="background-color: #f8f9fa;">
                                                <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e9ecef; font-weight: 600; color: #495057;">类型</th>
                                                <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e9ecef; font-weight: 600; color: #495057;">文件名称</th>
                                                <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e9ecef; font-weight: 600; color: #495057;">Content-Type</th>
                                                <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e9ecef; font-weight: 600; color: #495057;">Charset</th>
                                                <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e9ecef; font-weight: 600; color: #495057;">Content-Transfer-Encoding</th>
                                                <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e9ecef; font-weight: 600; color: #495057;">Content-Disposition</th>
                                                <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e9ecef; font-weight: 600; color: #495057;">内容</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            ${smtpDetails.emailContent.mimeParts.map(part => `
                                                <tr style="border-bottom: 1px solid #e9ecef;">
                                                    <td style="padding: 12px; font-weight: bold; color: ${part.type === '纯文本' ? '#27ae60' : part.type === 'HTML' ? '#3498db' : '#f39c12'};">${part.type}</td>
                                                    <td style="padding: 12px; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: help;" title="${htmlEscape(part.filename || '-')}">${htmlEscape(part.filename || '-')}</td>
                                                    <td style="padding: 12px; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: help;" title="${htmlEscape(part.contentType)}">${htmlEscape(part.contentType)}</td>
                                                    <td style="padding: 12px; max-width: 100px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: help;" title="${htmlEscape(part.charset || '-')}">${htmlEscape(part.charset || '-')}</td>
                                                    <td style="padding: 12px; max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: help;" title="${htmlEscape(part.contentTransferEncoding || '-')}">${htmlEscape(part.contentTransferEncoding || '-')}</td>
                                                    <td style="padding: 12px; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: help;" title="${htmlEscape(part.contentDisposition || '-')}">${htmlEscape(part.contentDisposition || '-')}</td>
                                                    <td style="padding: 12px; max-width: 300px; line-height: 1.5; max-height: 4.5em; overflow: hidden; text-overflow: ellipsis; display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; cursor: help; white-space: normal;" title="${htmlEscape(part.content)}">${htmlEscape(part.content)}</td>
                                                </tr>
                                            `).join('')}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        ` : ''}
                        
                        <!-- 传统邮件内容显示作为备用 -->
                        ${(smtpDetails.emailContent.plain || smtpDetails.emailContent.html) && (!smtpDetails.emailContent.mimeParts || smtpDetails.emailContent.mimeParts.length === 0) ? `
                            <div>
                                <div style="font-weight: 500; color: #666; font-size: 13px; margin-bottom: 15px;">邮件内容（传统显示）</div>
                                <div style="display: grid; grid-template-columns: 1fr; gap: 15px;">
                                    ${smtpDetails.emailContent.plain ? `
                                        <div>
                                            <div style="font-weight: 500; color: #666; font-size: 13px; margin-bottom: 8px;">纯文本内容（原文）：</div>
                                            ${smtpDetails.emailContent.plainContentType ? `
                                                <div style="color: #333; font-size: 13px; margin-bottom: 5px;">Content-Type: ${htmlEscape(smtpDetails.emailContent.plainContentType)}</div>
                                            ` : ''}
                                            <div style="color: #333; font-size: 13px; margin-bottom: 5px;">Charset: ${smtpDetails.emailContent.plainCharset ? htmlEscape(smtpDetails.emailContent.plainCharset) : '未提取到'}</div>
                                            <div style="color: #333; font-size: 13px; padding: 10px; background-color: #f9f9f9; border-radius: 4px; white-space: pre-wrap; word-break: break-word; font-family: monospace; line-height: 1.5; max-height: 4.5em; overflow: hidden; text-overflow: ellipsis; display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; cursor: help;">${htmlEscape(smtpDetails.emailContent.plain)}</div>
                                        </div>
                                    ` : ''}
                                    ${smtpDetails.emailContent.html ? `
                                        <div>
                                            <div style="font-weight: 500; color: #666; font-size: 13px; margin-bottom: 8px;">HTML内容（原文）：</div>
                                            ${smtpDetails.emailContent.htmlContentType ? `
                                                <div style="color: #333; font-size: 13px; margin-bottom: 5px;">Content-Type: ${htmlEscape(smtpDetails.emailContent.htmlContentType)}</div>
                                            ` : ''}
                                            <div style="color: #333; font-size: 13px; margin-bottom: 5px;">Charset: ${smtpDetails.emailContent.htmlCharset ? htmlEscape(smtpDetails.emailContent.htmlCharset) : '未提取到'}</div>
                                            <div style="color: #333; font-size: 13px; padding: 10px; background-color: #f9f9f9; border-radius: 4px; white-space: pre-wrap; word-break: break-word; font-family: monospace; line-height: 1.5; max-height: 4.5em; overflow: hidden; text-overflow: ellipsis; display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; cursor: help;">${htmlEscape(smtpDetails.emailContent.html)}</div>
                                        </div>
                                    ` : ''}
                                </div>
                            </div>
                        ` : ''}
                    ` : `
                        <div style="color: #666; font-size: 13px; text-align: center;">无邮件内容</div>
                    `}
                </div>
                
                <!-- 附件信息 -->
                <div style="margin-bottom: 15px; padding: 15px; background-color: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);">
                    <div style="font-weight: bold; color: #3498db; margin-bottom: 15px;">附件信息</div>
                    ${smtpDetails.attachments.length > 0 ? `
                        <div style="overflow-x: auto;">
                            <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                                <thead>
                                    <tr style="background-color: #f8f9fa;">
                                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #e9ecef; font-weight: 600; color: #495057;">文件名</th>
                                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #e9ecef; font-weight: 600; color: #495057;">类型</th>
                                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #e9ecef; font-weight: 600; color: #495057;">编码</th>
                                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #e9ecef; font-weight: 600; color: #495057;">字符集</th>
                                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #e9ecef; font-weight: 600; color: #495057;">Content-Disposition</th>
                                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #e9ecef; font-weight: 600; color: #495057;">内容</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${smtpDetails.attachments.map((attach, index) => `
                                        <tr style="border-bottom: 1px solid #e9ecef;">
                                            <td style="padding: 10px;">${htmlEscape(attach.name || `附件${index + 1}`)}</td>
                                            <td style="padding: 10px;">${htmlEscape(attach.contentType || '-')}</td>
                                            <td style="padding: 10px;">${htmlEscape(attach.contentTransferEncoding || '-')}</td>
                                            <td style="padding: 10px;">${htmlEscape(attach.charset || '-')}</td>
                                            <td style="padding: 10px;">${htmlEscape(attach.contentDisposition || '-')}</td>
                                            <td style="padding: 10px; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: help;" title="${htmlEscape(attach.content || '-')}">${htmlEscape(attach.content || '-')}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    ` : `
                        <div style="color: #666; text-align: center; padding: 20px; background-color: #f8f9fa; border-radius: 4px;">
                            没有检测到附件
                        </div>
                    `}
                </div>
                
                <div style="margin-bottom: 15px;">
                    <div style="font-weight: bold; color: #3498db; margin-bottom: 10px;">SMTP命令</div>
                    <div style="background-color: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1); padding: 10px;">
                        ${smtpDetails.commands.map(cmd => `
                            <div style="margin-bottom: 5px; padding: 5px 10px; background-color: #f0f8ff; border-left: 3px solid #3498db; color: #333;">
                                <strong>${cmd.type}:</strong> ${cmd.content}
                            </div>
                        `).join('')}
                    </div>
                </div>
                
                <div>
                    <div style="font-weight: bold; color: #3498db; margin-bottom: 10px;">服务器响应</div>
                    <div style="background-color: #fff; border-radius: 4px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1); padding: 10px;">
                        ${smtpDetails.responses.map(resp => `
                            <div style="margin-bottom: 5px; padding: 5px 10px; background-color: #f0fff0; border-left: 3px solid #27ae60; color: #333;">
                                <strong>${resp.type} (${resp.description}):</strong> ${resp.content}
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    }
    
    // 按照时间排序消息
    const sortedMessages = [...stream.conversation].sort((a, b) => a.timestamp - b.timestamp);
    
    // 找到流对话section容器
    const flowSection = conversationDiv.closest('.flow-section');
    
    // 检查是否已经存在SMTP详情div或HTTP详情div，如果存在则移除
    const existingSmtpDiv = flowSection.querySelector('.smtp-details');
    if (existingSmtpDiv) {
        existingSmtpDiv.remove();
    }
    
    // 移除可能存在的HTTP详情div
    const existingHttpDiv = flowSection.querySelector('.http-details');
    if (existingHttpDiv) {
        existingHttpDiv.remove();
    }
    
    // 显示流对话内容
    let conversationHtml = `
        <div style="max-height: 700px; overflow-y: auto;">
            <!-- 流基本信息 -->
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background: #f5f5f5; border-radius: 6px; margin-bottom: 4px;">
                <h3 style="margin: 0; font-size: 14px; font-weight: 600; color: #333;">流 ${streamId} | ${stream.srcIp}:${stream.srcPort} → ${stream.dstIp}:${stream.dstPort} | 协议: ${mainProtocol} | 共${stream.packets.length}个数据包</h3>
                <button onclick="copyFullConversation('${streamId}')" style="padding: 4px 8px; background-color: #3b82f6; color: white; border: none; border-radius: 4px; font-size: 11px; cursor: pointer;">复制完整对话</button>
            </div>
            
            <!-- 对话内容，使用表格布局 -->
            <div style="display: table; width: 100%;">`;
    
    // 遍历对话消息
    sortedMessages.forEach((msg, index) => {
        // 构建消息内容
        const msgContent = msg.raw || msg.info;
        
        // 根据方向设置字体颜色
        const isOutgoing = msg.direction === '→';
        const fontColor = isOutgoing ? '#e53e3e' : '#3b82f6'; // 红色发送，蓝色接收
        
        // 找到对应的数据包
        const packet = getPacketById(msg.uniqueId);
        const packetIndex = packet ? currentPackets.findIndex(p => p.uniqueId === packet.uniqueId) : -1;
        
        // 显示为表格行，包含数据包ID列和消息内容列
        // 改进：确保所有数据包ID都可点击，使用findIndex直接查找索引
        const actualPacketIndex = currentPackets.findIndex(p => p.uniqueId === msg.uniqueId);
        // 如果在currentPackets中找不到，尝试在originalPackets中查找并获取正确索引
        let finalPacketIndex = actualPacketIndex;
        if (finalPacketIndex === -1) {
            const originalIndex = originalPackets.findIndex(p => p.uniqueId === msg.uniqueId);
            if (originalIndex !== -1) {
                // 如果在originalPackets中找到，使用该索引，showPacketDetails函数会处理转换
                finalPacketIndex = originalIndex;
            }
        }
        // 只有当确实找不到数据包时，才显示纯文本，否则都显示可点击链接
        const packetIdHtml = finalPacketIndex !== -1 ? 
            `<a href="javascript:void(0);" onclick="showPacketDetails(${finalPacketIndex});" style="color: #3498db; text-decoration: underline; cursor: pointer; user-select: none;">${msg.uniqueId}</a>` : 
            `${msg.uniqueId}`;
        // 确保消息内容单元格始终有内容，避免表格布局错乱
        const safeMsgContent = msgContent || ' '; // 如果内容为空，使用一个空格字符
        conversationHtml += `<div style="display: table-row; border-bottom: 1px solid #f0f0f0;"><div style="display: table-cell; vertical-align: top; padding: 2px 8px; min-width: 60px; width: 60px; text-align: right; font-size: 11px; color: #666; background-color: #fafafa; border-right: 1px solid #eee; user-select: none;">${packetIdHtml}</div><div style="display: table-cell; vertical-align: top; padding: 2px 8px; font-family: 'Courier New', Courier, monospace; font-size: 13px; line-height: 1.2; white-space: pre-wrap; word-break: break-all;"><span style="color: ${fontColor};">${htmlEscape(safeMsgContent)}</span></div></div>`;
    });
    
    conversationHtml += `
            </div>
        </div>
    `;
    
    // 设置流对话内容
    conversationDiv.innerHTML = conversationHtml;
    
    // 更新导航按钮状态
    updateNavigationButtons(streamId);
    
    // 如果是SMTP协议，创建独立的SMTP详情div并插入到流对话前面
    if (mainProtocol === 'SMTP') {
        const smtpDetails = parseSmtpDetails(sortedMessages);
        const smtpDetailsHtml = generateSmtpDetailsHtml(smtpDetails);
        
        // 创建SMTP详情div
        const smtpDetailsDiv = document.createElement('div');
        smtpDetailsDiv.className = 'smtp-details';
        smtpDetailsDiv.innerHTML = smtpDetailsHtml;
        
        // 将SMTP详情div插入到流对话div之前
        flowSection.insertBefore(smtpDetailsDiv, conversationDiv);
    } 
    // 如果是HTTP或HTTPS协议，或者流中包含HTTP对话消息，创建独立的HTTP详情div并插入到流对话前面
    else if (mainProtocol === 'HTTP' || mainProtocol === 'HTTPS' || 
             sortedMessages.some(msg => msg.protocol === 'HTTP')) {
        const httpDetails = parseHttpDetails(sortedMessages);
        const httpDetailsHtml = generateHttpDetailsHtml(httpDetails);
        
        // 创建HTTP详情div
        const httpDetailsDiv = document.createElement('div');
        httpDetailsDiv.className = 'http-details';
        httpDetailsDiv.innerHTML = httpDetailsHtml;
        
        // 将HTTP详情div插入到流对话div之前
        flowSection.insertBefore(httpDetailsDiv, conversationDiv);
    }
    
    // 显示数据包列表（与流对话div同一层级）
    showPacketsTable(stream);
}

// 显示数据包列表（与流对话div同一层级）
function showPacketsTable(stream) {
    // 先清除现有的数据包列表
    const existingPacketsTableDiv = document.getElementById('packetsTableContainer');
    if (existingPacketsTableDiv) {
        existingPacketsTableDiv.remove();
    }
    
    // 创建数据包列表容器
    const packetsTableDiv = document.createElement('div');
    packetsTableDiv.id = 'packetsTableContainer';
    packetsTableDiv.style.marginTop = '20px';
    
    // 生成数据包列表HTML
    let html = `
        <h4 style="margin: 0 0 10px 0; font-size: 14px; font-weight: 600; color: #333;">数据包列表</h4>
        <div style="max-height: 300px; overflow-y: auto;">
            <table class="packets-table" style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr>
                        <th style="padding: 8px; text-align: left; background-color: #f5f5f5; border: 1px solid #ddd;">数据包ID</th>
                        <th style="padding: 8px; text-align: left; background-color: #f5f5f5; border: 1px solid #ddd;">内容</th>
                        <th style="padding: 8px; text-align: left; background-color: #f5f5f5; border: 1px solid #ddd;">操作</th>
                    </tr>
                </thead>
                <tbody>`;
    
    // 遍历流的数据包，生成表格行
    stream.packets.forEach(packetId => {
        const packet = getPacketById(packetId);
        if (packet) {
        // 找到对应的对话消息
        const msg = stream.conversation.find(msg => msg.uniqueId === packet.uniqueId);
        const msgContent = msg ? (msg.raw || msg.info) : '';
        
        // 获取数据包在原始数组中的索引
        const packetIndex = originalPackets.findIndex(p => p.uniqueId === packet.uniqueId);
        
        html += `
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', Courier, monospace; font-size: 12px;">${packet.uniqueId}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', Courier, monospace; font-size: 12px; max-width: 500px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${htmlEscape(msgContent)}</td>
                <td style="padding: 8px; border: 1px solid #ddd; text-align: center;">
                    <button onclick="showPacketDetails(${packetIndex})" style="padding: 4px 8px; background-color: #3b82f6; color: white; border: none; border-radius: 4px; font-size: 11px; cursor: pointer;">查看详情</button>
                </td>
            </tr>
        `;
        }
    });
    
    html += `
                </tbody>
            </table>
        </div>
    `;
    
    packetsTableDiv.innerHTML = html;
    
    // 将数据包列表插入到流对话div后面
    const conversationDiv = document.getElementById('flowConversation');
    if (conversationDiv && conversationDiv.parentNode) {
        // 使用流对话div的父元素作为插入点，确保它们是同一层级
        conversationDiv.parentNode.insertBefore(packetsTableDiv, conversationDiv.nextSibling);
    } else {
        // 如果找不到流对话div或其父元素，显示错误信息
        console.error('无法找到流对话div或其父元素');
    }
}

// 复制单条消息
function copyMessage(uniqueId, streamId) {
    const stream = currentStreams[streamId];
    if (!stream) return;
    
    const message = stream.conversation.find(msg => msg.uniqueId === uniqueId);
    if (!message) return;
    
    const msgContent = message.raw || message.info;
    
    navigator.clipboard.writeText(msgContent).then(() => {
        // 显示复制成功提示
        showCopyNotification('单条消息已复制到剪贴板');
    }).catch(err => {
        console.error('复制失败:', err);
        alert('复制失败，请手动复制');
    });
}

// 复制完整对话
function copyFullConversation(streamId) {
    const stream = currentStreams[streamId];
    if (!stream || stream.conversation.length === 0) return;
    
    // 按照时间排序消息
    const sortedMessages = [...stream.conversation].sort((a, b) => a.timestamp - b.timestamp);
    
    // 合并所有消息内容
    let fullConversation = `=== 流对话 (流ID: ${streamId}) ===\n`;
    fullConversation += `源地址: ${stream.srcIp}:${stream.srcPort}\n`;
    fullConversation += `目标地址: ${stream.dstIp}:${stream.dstPort}\n`;
    fullConversation += `数据包数量: ${stream.packets.length}\n`;
    fullConversation += `=== 对话内容 ===\n\n`;
    
    sortedMessages.forEach(msg => {
        const msgContent = msg.raw || msg.info;
        fullConversation += `${msgContent}

`;
    });
    
    // 处理分块数据，合并连续的数据包
    const chunkedData = {};
    
    // 尝试识别分块数据
    sortedMessages.forEach(msg => {
        const content = msg.raw || msg.info;
        // 检查是否包含分块标识，例如 "ID: 9863 → 9923"
        const chunkMatch = content.match(/ID:\s*(\d+)\s*→\s*(\d+)/);
        if (chunkMatch) {
            const startId = parseInt(chunkMatch[1]);
            const endId = parseInt(chunkMatch[2]);
            const chunkKey = `${startId}-${endId}`;
            
            if (!chunkedData[chunkKey]) {
                chunkedData[chunkKey] = [];
            }
            chunkedData[chunkKey].push(content);
        }
    });
    
    // 如果有分块数据，添加到完整对话末尾
    if (Object.keys(chunkedData).length > 0) {
        fullConversation += `=== 合并的分块数据 ===\n\n`;
        
        for (const [chunkKey, chunks] of Object.entries(chunkedData)) {
            fullConversation += `--- 分块 ${chunkKey} ---\n`;
            chunks.forEach(chunk => {
                // 提取实际数据内容，去除分块标识
                const dataContent = chunk.replace(/ID:\s*\d+\s*→\s*\d+\s*/, '');
                fullConversation += dataContent;
            });
            fullConversation += `\n\n`;
        }
    }
    
    navigator.clipboard.writeText(fullConversation).then(() => {
        // 显示复制成功提示
        showCopyNotification('完整对话已复制到剪贴板，包括合并的分块数据');
    }).catch(err => {
        console.error('复制失败:', err);
        alert('复制失败，请手动复制');
    });
}

// 更新导航按钮状态
function updateNavigationButtons(currentStreamId) {
    // 显示导航按钮
    const prevBtn = document.getElementById('prevFlowBtn');
    const nextBtn = document.getElementById('nextFlowBtn');
    const streamIdSpan = document.getElementById('currentStreamId');
    
    if (prevBtn && nextBtn) {
        prevBtn.style.display = 'inline-block';
        nextBtn.style.display = 'inline-block';
        
        // 保存当前流ID到按钮的data属性中
        prevBtn.setAttribute('data-stream-id', currentStreamId);
        nextBtn.setAttribute('data-stream-id', currentStreamId);
    }
    
    // 更新流ID显示
    if (streamIdSpan) {
        streamIdSpan.textContent = `流ID: ${currentStreamId}`;
    }
}

// 显示上一条流
function showPrevFlow() {
    // 从按钮的data属性中获取当前流ID
    const prevBtn = document.getElementById('prevFlowBtn');
    if (!prevBtn) return;
    
    const currentStreamId = prevBtn.getAttribute('data-stream-id');
    if (!currentStreamId) return;
    
    // 获取所有流ID并排序
    const streamIds = Object.keys(currentStreams).sort((a, b) => {
        // 尝试将流ID转换为数字进行比较，确保顺序正确
        const aNum = parseInt(a);
        const bNum = parseInt(b);
        if (!isNaN(aNum) && !isNaN(bNum)) {
            return aNum - bNum;
        }
        return a.localeCompare(b);
    });
    
    // 找到当前流的索引
    const currentIndex = streamIds.indexOf(currentStreamId);
    if (currentIndex > 0) {
        // 显示上一条流
        const prevStreamId = streamIds[currentIndex - 1];
        showFlowConversation(prevStreamId);
    }
}

// 显示下一条流
function showNextFlow() {
    // 从按钮的data属性中获取当前流ID
    const nextBtn = document.getElementById('nextFlowBtn');
    if (!nextBtn) return;
    
    const currentStreamId = nextBtn.getAttribute('data-stream-id');
    if (!currentStreamId) return;
    
    // 获取所有流ID并排序
    const streamIds = Object.keys(currentStreams).sort((a, b) => {
        // 尝试将流ID转换为数字进行比较，确保顺序正确
        const aNum = parseInt(a);
        const bNum = parseInt(b);
        if (!isNaN(aNum) && !isNaN(bNum)) {
            return aNum - bNum;
        }
        return a.localeCompare(b);
    });
    
    // 找到当前流的索引
    const currentIndex = streamIds.indexOf(currentStreamId);
    if (currentIndex < streamIds.length - 1) {
        // 显示下一条流
        const nextStreamId = streamIds[currentIndex + 1];
        showFlowConversation(nextStreamId);
    }
}

// 显示复制成功通知
function showCopyNotification(message) {
    // 检查是否已存在通知元素
    let notification = document.getElementById('copyNotification');
    if (!notification) {
        notification = document.createElement('div');
        notification.id = 'copyNotification';
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #4caf50;
            color: white;
            padding: 12px 20px;
            border-radius: 6px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            z-index: 10000;
            font-size: 14px;
            font-weight: 500;
            opacity: 0;
            transition: opacity 0.3s ease, transform 0.3s ease;
            transform: translateY(-20px);
        `;
        document.body.appendChild(notification);
    }
    
    notification.textContent = message;
    notification.style.opacity = '1';
    notification.style.transform = 'translateY(0)';
    
    // 3秒后自动隐藏
    setTimeout(() => {
        notification.style.opacity = '0';
        notification.style.transform = 'translateY(-20px)';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, 3000);
}

// 生成表格HTML的辅助函数
function generateLldpTable(lldpData, title) {
    if (!lldpData || !lldpData.tlvList) {
        return `<h4>${title}</h4><p style="color: #666; margin-left: 20px;">未解析</p>`;
    }
    
    const tlvList = lldpData.tlvList;
    
    let html = `<h4>${title}</h4><table style="width: 100%; border-collapse: collapse; margin-top: 10px; margin-left: 20px;">
                <tr>
                    <th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd; width: 250px;">属性</th>
                    <th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd;">值</th>
                </tr>`;
    
    // LLDP TLV类型中文名称映射
    const tlvTypeNames = {
        0: 'End of LLDPDU (结束标记)',
        1: 'Chassis ID (设备ID)',
        2: 'Port ID (端口ID)',
        3: 'Time to Live (生存时间)',
        4: 'Port Description (端口描述)',
        5: 'System Name (系统名称)',
        6: 'System Description (系统描述)',
        7: 'System Capabilities (系统能力)',
        8: 'Management Address (管理地址)',
        127: 'Organization Specific (组织特定)'
    };
    
    // LLDP Chassis ID子类型中文名称映射
    const chassisIdSubtypes = {
        1: 'Chassis component (设备组件)',
        2: 'Interface alias (接口别名)',
        3: 'Port component (端口组件)',
        4: 'MAC address (MAC地址)',
        5: 'Network address (网络地址)',
        6: 'Interface name (接口名称)',
        7: 'Locally assigned (本地分配)'
    };
    
    // LLDP Port ID子类型中文名称映射
    const portIdSubtypes = {
        1: 'Interface alias (接口别名)',
        2: 'Port component (端口组件)',
        3: 'MAC address (MAC地址)',
        4: 'Network address (网络地址)',
        5: 'Interface name (接口名称)',
        6: 'Agent circuit ID (代理电路ID)',
        7: 'Locally assigned (本地分配)'
    };
    
    // 系统能力映射
    const systemCapabilities = {
        1: 'Other (其他)',
        2: 'Repeater (中继器)',
        4: 'Bridge (网桥)',
        8: 'WLAN Access Point (无线接入点)',
        16: 'Router (路由器)',
        32: 'Telephone (电话)',
        64: 'DOCSIS Cable Device (DOCSIS电缆设备)',
        128: 'Station Only (仅工作站)'
    };
    
    // 遍历每个TLV
    lldpData.tlvList.forEach((tlv, index) => {
        // TLV头部信息
        html += `<tr>
                    <td style="padding: 12px 8px; border: 1px solid #ddd; background-color: #f0f7ff; font-weight: bold; font-family: Arial, sans-serif;">TLV ${index + 1}: ${tlvTypeNames[tlv.type] || `Unknown (${tlv.type})`}</td>
                    <td style="padding: 12px 8px; border: 1px solid #ddd; background-color: #f0f7ff; font-family: Arial, sans-serif;"></td>
                </tr>`;
        
        // TLV类型和长度信息
        html += `<tr>
                    <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">类型 (Type)</td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${tlv.type} - ${tlv.typeName}</td>
                </tr>`;
        
        html += `<tr>
                    <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">长度 (Length)</td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${tlv.length} bytes</td>
                </tr>`;
        
        // 根据TLV类型显示详细信息
        switch (tlv.type) {
            case 1: // Chassis ID
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">设备ID子类型 (Chassis Id Subtype)</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${tlv.subtype} - ${chassisIdSubtypes[tlv.subtype] || `Unknown (${tlv.subtype})`}</td>
                        </tr>`;
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">设备ID (Chassis Id)</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${htmlEscape(tlv.chassisId)} (0x${tlv.chassisIdBytes})</td>
                        </tr>`;
                break;
                
            case 2: // Port ID
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">端口ID子类型 (Port Id Subtype)</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${tlv.subtype} - ${portIdSubtypes[tlv.subtype] || `Unknown (${tlv.subtype})`}</td>
                        </tr>`;
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">端口ID (Port Id)</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${htmlEscape(tlv.portId)} (0x${tlv.portIdBytes})</td>
                        </tr>`;
                break;
                
            case 3: // Time to Live
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">生存时间 (Seconds)</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${tlv.seconds} 秒</td>
                        </tr>`;
                if (tlv.normalLldpdu) {
                    html += `<tr>
                                <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">标记</td>
                                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; color: #27ae60; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">Normal LLDPDU (正常LLDP数据单元)</td>
                            </tr>`;
                }
                break;
                
            case 5: // System Name
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">系统名称 (System Name)</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${htmlEscape(tlv.systemName)}</td>
                        </tr>`;
                break;
                
            case 6: // System Description
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">系统描述 (System Description)</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${htmlEscape(tlv.systemDescription)}</td>
                        </tr>`;
                break;
                
            case 7: // System Capabilities
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">系统能力 (System Capabilities)</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">0x${tlv.systemCapabilities.toString(16).padStart(4, '0')}</td>
                        </tr>`;
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">启用的能力 (Enabled Capabilities)</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">0x${tlv.enabledCapabilities.toString(16).padStart(4, '0')}</td>
                        </tr>`;
                
                // 解析能力值
                if (tlv.systemCapabilities) {
                    const capabilitiesList = [];
                    for (const [bit, name] of Object.entries(systemCapabilities)) {
                        if (tlv.systemCapabilities & parseInt(bit)) {
                            const enabled = (tlv.enabledCapabilities & parseInt(bit)) ? ' (已启用)' : ' (已禁用)';
                            capabilitiesList.push(name + enabled);
                        }
                    }
                    if (capabilitiesList.length > 0) {
                        html += `<tr>
                                    <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">能力详情</td>
                                    <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${capabilitiesList.join(', ')}</td>
                                </tr>`;
                    }
                }
                break;
                
            case 8: // Management Address
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">管理地址 (Management Address)</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${htmlEscape(tlv.managementAddress || 'N/A')}</td>
                        </tr>`;
                if (tlv.interfaceSubtype) {
                    html += `<tr>
                                <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">接口子类型 (Interface Subtype)</td>
                                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${tlv.interfaceSubtype}</td>
                            </tr>`;
                }
                if (tlv.interfaceNumber) {
                    html += `<tr>
                                <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">接口编号 (Interface Number)</td>
                                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${tlv.interfaceNumber}</td>
                            </tr>`;
                }
                break;
                
            case 127: // Organization Specific
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">组织唯一标识符 (OUI)</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${tlv.oui || 'N/A'}</td>
                        </tr>`;
                if (tlv.subtype !== undefined) {
                    html += `<tr>
                                <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">子类型 (Subtype)</td>
                                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${tlv.subtype}</td>
                            </tr>`;
                }
                break;
        }
        
        // 显示原始值（十六进制）
        html += `<tr>
                    <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif; font-family: monospace;">原始值 (Hex)</td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: monospace; white-space: pre-wrap; word-wrap: break-word;">${htmlEscape(tlv.value)}</td>
                </tr>`;
    });
    
    html += '</table>';
    return html;
}

function generateTable(data, title) {
    if (!data) {
        return `<h4>${title}</h4><p style="color: #666; margin-left: 20px;">未解析</p>`;
    }
    
    let html = `<h4>${title}</h4><table style="width: 100%; border-collapse: collapse; margin-top: 10px; margin-left: 20px;">
                <tr>
                    <th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd; width: 200px;">属性</th>
                    <th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd;">值</th>
                </tr>`;
    
    // 属性中文解释映射
    const propertyLabels = {
        srcMac: '源物理地址',
        dstMac: '目标物理地址',
        srcIp: '源IP地址',
        dstIp: '目标IP地址',
        srcPort: '源端口',
        dstPort: '目标端口',
        protocol: '协议类型',
        version: '版本',
        headerLength: '首部长度',
        ttl: '生存时间',
        checksum: '校验和',
        flags: '标志',
        windowSize: '窗口大小',
        seq: '序列号',
        ack: '确认号',
        length: '长度',
        streamId: '流ID',
        uniqueId: '唯一ID',
        timestamp: '时间戳',
        capturedLen: '捕获长度',
        packetLen: '原始长度',
        // ICMP/ICMPv6属性
        icmpType: '类型',
        icmpVersion: 'ICMP版本',
        code: '代码',
        groupAddress: '组地址',
        identifier: '标识符',
        sequence: '序列号',
        // HTTP请求属性
        method: '请求方法',
        path: '请求路径',
        httpVersion: 'HTTP版本',
        statusCode: '状态码',
        statusText: '状态文本',
        headers: '请求头',
        body: '请求体',
        responseHeaders: '响应头',
        responseBody: '响应体',
        host: '主机地址',
        userAgent: '用户代理',
        cookie: 'Cookie信息',
        contentType: '内容类型',
        contentLength: '内容长度',
        accept: '接受的内容类型',
        acceptLanguage: '接受的语言',
        server: '服务器信息',
        location: '重定向地址',
        connection: '连接状态',
        cacheControl: '缓存控制',
        expires: '过期时间',
        lastModified: '最后修改时间',
        etag: '实体标签',
        vary: '缓存变体',
        transferEncoding: '传输编码',
        postParams: 'POST参数',
        // HTTP信息对象属性
        raw: '原始数据',
        httpInfo: 'HTTP信息',
        responseTime: '响应时间',
        // USB属性
        busId: '总线号',
        deviceAddress: '设备地址',
        endpointAddress: '端点地址',
        transferType: '传输类型',
        endpointNum: '端点号',
        transferDirection: '传输方向',
        hasSetupPacket: '是否有Setup Packet',
        dataLength: '数据长度',
        urbFunction: 'URB函数',
        setup: 'Setup Packet',
        setupPacket: 'Setup Packet十六进制',
        bmRequestType: '请求类型',
        bRequest: '请求码',
        wValue: '值',
        wIndex: '索引',
        wLength: '数据长度',
        requestName: '请求名称',
        descriptorType: '描述符类型',
        descriptorIndex: '描述符索引',
        dataPayload: '实际数据负载',
        headerLength: '伪头部长度',
        usbdStatus: 'USBD状态码',
        urbFunctionCode: 'URB功能代码',
        // BLE属性
        type: '类型',
        typeHex: '类型十六进制',
        rawData: '原始数据',
        opcode: '操作码',
        opcodeHex: '操作码十六进制',
        offset: '偏移量',
        parameters: '参数',
        accessAddress: '访问地址',
        accessAddressHex: '访问地址十六进制',
        packetType: '数据包类型',
        packetTypeValue: '数据包类型值',
        packetTypeHex: '数据包类型十六进制',
        header: '头部',
        headerHex: '头部十六进制',
        headerRaw: '原始头部',
        headerDetails: '头部详情',
        advAddress: '广播地址',
        advAddressType: '广播地址类型',
        advertisingAddress: 'Advertising Address',
        advertisingAddressType: 'Advertising Address Type',
        initiatorAddress: 'Initiator Address',
        initiatorAddressType: 'Initiator Address Type',
        centralAddress: 'Central Address',
        centralAddressType: 'Central Address Type',
        peripheralAddress: 'Peripheral Address',
        peripheralAddressType: 'Peripheral Address Type',
        payload: '有效负载',
        opCodeName: '操作码名称',
        opCode: '操作码',
        opCodeHex: '操作码十六进制',
        lengthField: '长度字段',
        channelId: '通道ID',
        channelIdHex: '通道ID十六进制',
        channelName: '通道名称'
    };
    
    for (const [key, value] of Object.entries(data)) {
        // 跳过空值
        if (value === null || value === undefined) continue;
        
        // 对于HTTP信息对象，跳过顶层的重复属性（这些属性已经在headers中显示）
        const skipHttpTopLevelProperties = ['host', 'userAgent', 'contentType', 'contentLength', 'accept', 'acceptLanguage', 'cookie', 'server', 'location'];
        if (data.headers && skipHttpTopLevelProperties.includes(key)) continue;
        
        // 格式化键名，将驼峰命名转换为可读格式
        let formattedKey = key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
        
        // 添加中文解释
        if (propertyLabels[key]) {
            formattedKey += ` (${propertyLabels[key]})`;
        }
        
        // 特殊处理嵌套对象
        if (typeof value === 'object' && !Array.isArray(value)) {
            if (key === 'headers') {
                // 处理headers对象，展开显示
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; background-color: #f5f5f5; font-family: Arial, sans-serif;">${formattedKey}</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;"></td>
                        </tr>`;
                for (const [headerKey, headerValue] of Object.entries(value)) {
                    if (headerValue === null || headerValue === undefined) continue;
                    html += `<tr>
                                <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-family: Arial, sans-serif;">${headerKey}</td>
                                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${htmlEscape(headerValue)}</td>
                            </tr>`;
                }
            } else if (key === 'commandLine' || key === 'info' || key === 'requestParams') {
                // 长文本字段直接显示
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">${formattedKey}</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${htmlEscape(value)}</td>
                        </tr>`;
            } else if (key === 'setup') {
                // USB Setup Packet显示为表格
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; background-color: #f5f5f5; font-family: Arial, sans-serif;">${formattedKey}</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;"></td>
                        </tr>`;
                for (const [setupKey, setupValue] of Object.entries(value)) {
                    if (setupValue === null || setupValue === undefined) continue;
                    let formattedSetupKey = setupKey.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
                    // 添加中文解释
                    if (propertyLabels[setupKey]) {
                        formattedSetupKey += ` (${propertyLabels[setupKey]})`;
                    }
                    html += `<tr>
                                <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-weight: 500; font-family: Arial, sans-serif;">${formattedSetupKey}</td>
                                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${htmlEscape(setupValue)}</td>
                            </tr>`;
                }
            } else if (key === 'postParams') {
                // POST参数显示为表格
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; background-color: #f5f5f5; font-family: Arial, sans-serif;">${formattedKey}</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;"></td>
                        </tr>`;
                for (const [paramKey, paramValue] of Object.entries(value)) {
                    if (paramValue === null || paramValue === undefined) continue;
                    html += `<tr>
                                <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-weight: 500; font-family: Arial, sans-serif;">${paramKey}</td>
                                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${htmlEscape(paramValue)}</td>
                            </tr>`;
                }
            } else if (key === 'specialFormat' || key === 'll' || key === 'sm' || key === 'att' || key === 'l2cap' || key === 'basic' || key === 'nrfSnifferHeader') {
                // BLE协议相关嵌套对象，展开显示每个属性
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; background-color: #f5f5f5; font-family: Arial, sans-serif;">${formattedKey}</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;"></td>
                        </tr>`;
                for (const [bleKey, bleValue] of Object.entries(value)) {
                    if (bleValue === null || bleValue === undefined) continue;
                    let formattedBleKey = bleKey.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
                    // 添加中文解释
                    if (propertyLabels[bleKey]) {
                        formattedBleKey += ` (${propertyLabels[bleKey]})`;
                    }
                    // 特殊处理嵌套对象
                    if (typeof bleValue === 'object' && !Array.isArray(bleValue)) {
                        // 展开nrfSnifferHeader等嵌套对象
                        if (bleKey === 'nrfSnifferHeader') {
                            // 直接展开nrfSnifferHeader的属性，不使用额外的层级
                            for (const [nrfKey, nrfValue] of Object.entries(bleValue)) {
                                if (nrfValue === null || nrfValue === undefined) continue;
                                let formattedNrfKey = nrfKey.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
                                html += `<tr>
                                            <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-weight: 500; font-family: Arial, sans-serif;">${formattedNrfKey}</td>
                                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${htmlEscape(nrfValue)}</td>
                                        </tr>`;
                            }
                        } else {
                            // 其他嵌套对象，使用嵌套层级显示
                            html += `<tr>
                                        <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-weight: 500; font-family: Arial, sans-serif;">${formattedBleKey}</td>
                                        <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;"></td>
                                    </tr>`;
                            for (const [detailKey, detailValue] of Object.entries(bleValue)) {
                                if (detailValue === null || detailValue === undefined) continue;
                                let formattedDetailKey = detailKey.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
                                if (propertyLabels[detailKey]) {
                                    formattedDetailKey += ` (${propertyLabels[detailKey]})`;
                                }
                                html += `<tr>
                                            <td style="padding: 8px; border: 1px solid #ddd; padding-left: 60px; font-family: Arial, sans-serif;">${formattedDetailKey}</td>
                                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${htmlEscape(detailValue)}</td>
                                        </tr>`;
                            }
                        }
                    } else if (Array.isArray(bleValue)) {
                        // 处理数组类型，如advertisingDataStructures
                        html += `<tr>
                                    <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-weight: 500; font-family: Arial, sans-serif;">${formattedBleKey}</td>
                                    <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;"></td>
                                </tr>`;
                        // 显示数组中的每个元素
                        bleValue.forEach((item, index) => {
                            html += `<tr>
                                        <td style="padding: 8px; border: 1px solid #ddd; padding-left: 60px; font-weight: 500; font-family: Arial, sans-serif;">${formattedBleKey} ${index + 1}</td>
                                        <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;"></td>
                                    </tr>`;
                            // 显示数组元素的属性
                            if (typeof item === 'object' && item !== null) {
                                for (const [itemKey, itemValue] of Object.entries(item)) {
                                    if (itemValue === null || itemValue === undefined) continue;
                                    let formattedItemKey = itemKey.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
                                    html += `<tr>
                                                <td style="padding: 8px; border: 1px solid #ddd; padding-left: 80px; font-family: Arial, sans-serif;">${formattedItemKey}</td>
                                                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${htmlEscape(itemValue)}</td>
                                            </tr>`;
                                }
                            } else {
                                html += `<tr>
                                            <td style="padding: 8px; border: 1px solid #ddd; padding-left: 80px; font-family: Arial, sans-serif;">值</td>
                                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${htmlEscape(item)}</td>
                                        </tr>`;
                            }
                        });
                    } else {
                        // 普通BLE属性
                        html += `<tr>
                                    <td style="padding: 8px; border: 1px solid #ddd; padding-left: 40px; font-weight: 500; font-family: Arial, sans-serif;">${formattedBleKey}</td>
                                    <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${htmlEscape(bleValue)}</td>
                                </tr>`;
                    }
                }
            } else {
                // 其他嵌套对象，简单显示
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">${formattedKey}</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${htmlEscape(JSON.stringify(value, null, 2))}</td>
                        </tr>`;
            }
        } else {
            // 普通字段，检查是否需要多行显示
            // 对URL路径进行解码
            const displayValue = key === 'path' ? urlDecode(value) : value;
            const isLongText = typeof displayValue === 'string' && displayValue.length > 100;
            if (isLongText || key === 'commandLine' || key === 'info' || key === 'requestParams') {
                // 长文本字段直接显示
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">${formattedKey}</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${htmlEscape(displayValue)}</td>
                        </tr>`;
            } else {
                // 短文本或其他类型，普通显示
                html += `<tr>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">${formattedKey}</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">${htmlEscape(displayValue)}</td>
                        </tr>`;
            }
        }
    }
    
    html += `</table>`;
    return html;
}

function showPacketDetails(packetIndex) {
    // 保存当前数据包索引
    currentPacketIndex = packetIndex;
    
    let packet;
    
    // 先尝试在currentPackets中查找
    if (packetIndex < currentPackets.length) {
        packet = currentPackets[packetIndex];
    }
    
    // 如果没找到，尝试通过originalPackets查找
    if (!packet) {
        packet = originalPackets[packetIndex];
        // 如果在originalPackets中找到了，更新currentPacketIndex为它在currentPackets中的索引
        if (packet) {
            currentPacketIndex = currentPackets.findIndex(p => p.uniqueId === packet.uniqueId);
        }
    }
    
    if (!packet) return;
    
    // 切换到详情标签
    switchTab('details');
    
    const detailsDiv = document.getElementById('packetDetails');
    const hexData = PcapngParser.packetToHex(packet.data);
    
    // 生成导航按钮
    let navigationButtons = `<div style="margin-bottom: 20px; display: flex; gap: 10px; align-items: center;">
        <button id="prevPacketBtn" onclick="navigatePacket(-1)" ${currentPacketIndex === 0 ? 'disabled' : ''} 
                style="padding: 8px 16px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; ">
            上一个数据包
        </button>
        <button id="nextPacketBtn" onclick="navigatePacket(1)" ${currentPacketIndex === currentPackets.length - 1 ? 'disabled' : ''} 
                style="padding: 8px 16px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; ">
            下一个数据包
        </button>
        <span style="margin-left: 20px; font-weight: bold;">数据包 ${currentPacketIndex + 1} / ${currentPackets.length}</span>
    </div>`;
    
    // 生成各层协议表格
        const ethernetTable = generateTable(packet.layers?.link, '数据链路层 (以太网)');
        // 生成网络层表格，但LLDP协议除外（LLDP有专门的表格生成函数）
        let networkTable = '';
        if (packet.protocol !== 'LLDP') {
            networkTable = generateTable(packet.layers?.network, '网络层');
        }
        const transportTable = generateTable(packet.layers?.transport, '传输层');
        
        // 生成应用层协议表格
        let applicationTable = '';
        let smtpTable = '';
        let httpTable = '';
        let dnsTable = '';
        let icmpTable = '';
        let icmpv6Table = '';
        let igmpTable = '';
        let ssdpTable = '';
        let mdnsTable = '';
        let nbnsTable = '';
        let llmnrTable = '';
        let browserTable = '';
        let usbTable = '';
        let hciUsbTable = '';
        let lldpTable = '';
        let bleTable = '';
        
        if (packet.layers?.application) {
            // 创建应用层协议数据的副本，移除特定协议信息字段
            const appData = { ...packet.layers.application };
            const smtpInfo = appData.smtpInfo;
            const httpInfo = appData.httpInfo;
            const dnsInfo = appData.dnsInfo;
            const ssdpInfo = appData.ssdpInfo;
            const mdnsInfo = appData.mdnsInfo;
            const nbnsInfo = appData.nbnsInfo;
            const llmnrInfo = appData.llmnrInfo;
            const browserInfo = appData.browserInfo;
            
            delete appData.data; // 移除原始数据
            delete appData.smtpInfo; // 移除smtpInfo，单独处理
            delete appData.httpInfo; // 移除httpInfo，单独处理
            delete appData.dnsInfo; // 移除dnsInfo，单独处理
            delete appData.ssdpInfo; // 移除ssdpInfo，单独处理
            delete appData.mdnsInfo; // 移除mdnsInfo，单独处理
            delete appData.nbnsInfo; // 移除nbnsInfo，单独处理
            delete appData.llmnrInfo; // 移除llmnrInfo，单独处理
            delete appData.browserInfo; // 移除browserInfo，单独处理
            
            applicationTable = generateTable(appData, '应用层');
            
            // 如果是SMTP协议，生成SMTP层表格
            if (smtpInfo && packet.layers.application.protocol === 'SMTP') {
                smtpTable = generateTable(smtpInfo, 'SMTP 层');
            }
            
            // 如果是HTTP协议，生成HTTP层表格
            if (httpInfo && packet.layers.application.protocol === 'HTTP') {
                httpTable = generateTable(httpInfo, 'HTTP 层');
            }
            
            // 如果是DNS协议，生成DNS层表格
        if (dnsInfo && packet.layers.application.protocol === 'DNS') {
            // 处理DNS解析结果，添加解析后的域名和IP地址
            const dnsDisplayInfo = { ...dnsInfo };
            
            // DNS记录类型映射
            const dnsTypeMap = {
                1: 'A (Address)',
                28: 'AAAA (IPv6 Address)',
                5: 'CNAME (Canonical Name)',
                15: 'MX (Mail Exchange)',
                16: 'TXT (Text)',
                2: 'NS (Name Server)',
                6: 'SOA (Start of Authority)',
                12: 'PTR (Pointer)',
                33: 'SRV (Service Location)'
            };
            
            // DNS类别映射
            const dnsClassMap = {
                1: 'IN (Internet)',
                2: 'CS (CSNET)',
                3: 'CH (CHAOS)',
                4: 'HS (Hesiod)'
            };
            
            // 处理DNS查询，转换为可读字符串
            if (dnsDisplayInfo.queries && dnsDisplayInfo.queries.length > 0) {
                dnsDisplayInfo.queries = dnsDisplayInfo.queries.map((query, index) => 
                    `${index + 1}. ${query.name} (Type: ${dnsTypeMap[query.type] || query.type}, Class: ${dnsClassMap[query.class] || query.class})`
                ).join('\n');
            }
            
            // 处理DNS回答记录
            if (dnsDisplayInfo.answers && dnsDisplayInfo.answers.length > 0) {
                dnsDisplayInfo.answers = dnsDisplayInfo.answers.map((answer, index) => {
                    let answerStr = `${index + 1}. ${answer.name} (Type: ${dnsTypeMap[answer.type] || answer.type}, Class: ${dnsClassMap[answer.class] || answer.class}`;
                    if (answer.ttl) {
                        answerStr += `, TTL: ${answer.ttl}`;
                    }
                    if (answer.data) {
                        answerStr += `, Data: ${answer.data}`;
                    }
                    return answerStr + ')';
                }).join('\n');
            }
            
            // 处理DNS权威记录
            if (dnsDisplayInfo.authorities && dnsDisplayInfo.authorities.length > 0) {
                dnsDisplayInfo.authorities = dnsDisplayInfo.authorities.map((record, index) => {
                    let recordStr = `${index + 1}. ${record.name} (Type: ${dnsTypeMap[record.type] || record.type}, Class: ${dnsClassMap[record.class] || record.class}`;
                    if (record.ttl) {
                        recordStr += `, TTL: ${record.ttl}`;
                    }
                    if (record.data) {
                        recordStr += `, Data: ${record.data}`;
                    }
                    return recordStr + ')';
                }).join('\n');
            }
            
            // 处理DNS附加记录
            if (dnsDisplayInfo.additionals && dnsDisplayInfo.additionals.length > 0) {
                dnsDisplayInfo.additionals = dnsDisplayInfo.additionals.map((record, index) => {
                    let recordStr = `${index + 1}. ${record.name} (Type: ${dnsTypeMap[record.type] || record.type}, Class: ${dnsClassMap[record.class] || record.class}`;
                    if (record.ttl) {
                        recordStr += `, TTL: ${record.ttl}`;
                    }
                    if (record.data) {
                        recordStr += `, Data: ${record.data}`;
                    }
                    return recordStr + ')';
                }).join('\n');
            }
            
            // 如果有解析结果，添加到显示信息中
            if (dnsDisplayInfo.resolvedDomains && dnsDisplayInfo.resolvedDomains.length > 0) {
                dnsDisplayInfo.resolvedDomains = dnsDisplayInfo.resolvedDomains.map((item, index) => 
                    `${index + 1}. ${item.domain} → ${item.ip} (${item.type})`
                ).join('\n');
            }
            
            dnsTable = generateTable(dnsDisplayInfo, 'DNS 层');
        }
            
            // 如果是SSDP协议，生成SSDP层表格
            if (ssdpInfo && packet.layers.application.protocol === 'SSDP') {
                ssdpTable = generateTable(ssdpInfo, 'SSDP 层');
            }
            
            // 如果是MDNS协议，生成MDNS层表格
            if (mdnsInfo && packet.layers.application.protocol === 'MDNS') {
                const mdnsDisplayInfo = { ...mdnsInfo };
                
                // DNS记录类型映射
                const dnsTypeMap = {
                    1: 'A (Address)',
                    28: 'AAAA (IPv6 Address)',
                    5: 'CNAME (Canonical Name)',
                    15: 'MX (Mail Exchange)',
                    16: 'TXT (Text)',
                    2: 'NS (Name Server)',
                    6: 'SOA (Start of Authority)',
                    12: 'PTR (Pointer)',
                    33: 'SRV (Service Location)'
                };
                
                // DNS类别映射
                const dnsClassMap = {
                    1: 'IN (Internet)',
                    2: 'CS (CSNET)',
                    3: 'CH (CHAOS)',
                    4: 'HS (Hesiod)'
                };
                
                // 处理MDNS查询，转换为可读字符串
                if (mdnsDisplayInfo.queries && mdnsDisplayInfo.queries.length > 0) {
                    mdnsDisplayInfo.queries = mdnsDisplayInfo.queries.map((query, index) => 
                        `${index + 1}. ${query.name} (Type: ${dnsTypeMap[query.type] || query.type}, Class: ${dnsClassMap[query.class] || query.class})`
                    ).join('\n');
                }
                
                // 处理MDNS回答记录
                if (mdnsDisplayInfo.answers && mdnsDisplayInfo.answers.length > 0) {
                    mdnsDisplayInfo.answers = mdnsDisplayInfo.answers.map((answer, index) => {
                        let answerStr = `${index + 1}. ${answer.name} (Type: ${dnsTypeMap[answer.type] || answer.type}, Class: ${dnsClassMap[answer.class] || answer.class}`;
                        if (answer.ttl) {
                            answerStr += `, TTL: ${answer.ttl}`;
                        }
                        if (answer.data) {
                            answerStr += `, Data: ${answer.data}`;
                        }
                        return answerStr + ')';
                    }).join('\n');
                }
                
                mdnsTable = generateTable(mdnsDisplayInfo, 'MDNS 层');
            }
            
            // 如果是NBNS协议，生成NBNS层表格
            if (nbnsInfo && packet.layers.application.protocol === 'NBNS') {
                nbnsTable = generateTable(nbnsInfo, 'NBNS 层');
            }
            
            // 如果是LLMNR协议，生成LLMNR层表格
            if (llmnrInfo && packet.layers.application.protocol === 'LLMNR') {
                // 处理LLMNR解析结果，添加解析后的域名和IP地址
                const llmnrDisplayInfo = { ...llmnrInfo };
                
                // DNS记录类型映射
                const dnsTypeMap = {
                    1: 'A (Address)',
                    28: 'AAAA (IPv6 Address)',
                    5: 'CNAME (Canonical Name)',
                    15: 'MX (Mail Exchange)',
                    16: 'TXT (Text)',
                    2: 'NS (Name Server)',
                    6: 'SOA (Start of Authority)',
                    12: 'PTR (Pointer)',
                    33: 'SRV (Service Location)'
                };
                
                // DNS类别映射
                const dnsClassMap = {
                    1: 'IN (Internet)',
                    2: 'CS (CSNET)',
                    3: 'CH (CHAOS)',
                    4: 'HS (Hesiod)'
                };
                
                // 处理LLMNR查询，转换为可读字符串
                if (llmnrDisplayInfo.queries && llmnrDisplayInfo.queries.length > 0) {
                    llmnrDisplayInfo.queries = llmnrDisplayInfo.queries.map((query, index) => 
                        `${index + 1}. ${query.name} (Type: ${dnsTypeMap[query.type] || query.type}, Class: ${dnsClassMap[query.class] || query.class})`
                    ).join('\n');
                }
                
                // 处理LLMNR回答记录
                if (llmnrDisplayInfo.answers && llmnrDisplayInfo.answers.length > 0) {
                    llmnrDisplayInfo.answers = llmnrDisplayInfo.answers.map((answer, index) => {
                        let answerStr = `${index + 1}. ${answer.name} (Type: ${dnsTypeMap[answer.type] || answer.type}, Class: ${dnsClassMap[answer.class] || answer.class}`;
                        if (answer.ttl) {
                            answerStr += `, TTL: ${answer.ttl}`;
                        }
                        if (answer.data) {
                            answerStr += `, Data: ${answer.data}`;
                        }
                        return answerStr + ')';
                    }).join('\n');
                }
                
                // 如果有解析结果，添加到显示信息中
                if (llmnrDisplayInfo.resolvedDomains && llmnrDisplayInfo.resolvedDomains.length > 0) {
                    llmnrDisplayInfo.resolvedDomains = llmnrDisplayInfo.resolvedDomains.map((item, index) => 
                        `${index + 1}. ${item.domain} → ${item.ip} (${item.type})`
                    ).join('\n');
                }
                
                llmnrTable = generateTable(llmnrDisplayInfo, 'LLMNR 层');
            }
            
            // 如果是BROWSER协议，生成BROWSER层表格
            if (browserInfo && packet.layers.application.protocol === 'BROWSER') {
                browserTable = generateTable(browserInfo, 'BROWSER 层');
            }
        } else {
            applicationTable = '<h4>应用层</h4><p style="color: #666; margin-left: 20px;">未解析</p>';
        }
        
        // 处理USB协议
        if (packet.protocol === 'USB' && packet.layers?.link?.type === 'USB') {
            // 生成详细的USB协议分析
            usbTable = generateDetailedUsbInfo(packet, 'USB 层');
        }
        
        // 处理HCI_USB协议
        if (packet.protocol === 'HCI_USB' && packet.layers?.link?.type === 'USB') {
            const hciUsbData = { ...packet.layers.link };
            delete hciUsbData.type; // 已在标题中显示
            delete hciUsbData.linkType; // 已在标题中显示
            hciUsbTable = generateTable(hciUsbData, 'HCI_USB 层');
        }
        
        // 处理BLE协议，生成BLE层表格
        if (packet.protocol.startsWith('BLE') && packet.layers?.link?.type === 'BLE') {
            const bleData = { ...packet.layers.link };
            
            // 移除已经单独处理的子协议，避免重复显示
            const { l2cap, sm, att, basic, specialFormat, nrfSnifferHeader, ll, ...remainingBleData } = bleData;
            
            // 生成基本BLE信息表格
            let bleBasicTable = '<h4>BLE 层</h4>';
            if (Object.keys(remainingBleData).length > 0) {
                bleBasicTable = generateTable(remainingBleData, 'BLE 层');
            }
            
            // 生成LL层信息表格
            let bleLlTable = '';
            if (ll) {
                bleLlTable = generateTable(ll, 'BLE Link Layer (LL) 层');
            }
            
            // 生成特殊格式表格
            let bleSpecialFormatTable = '';
            if (specialFormat) {
                bleSpecialFormatTable = generateTable(specialFormat, 'BLE 特殊格式 层');
            }
            
            // 生成nRF Sniffer头部表格
            let bleNrfSnifferTable = '';
            if (nrfSnifferHeader) {
                bleNrfSnifferTable = generateTable(nrfSnifferHeader, 'nRF Sniffer 头部 层');
            }
            
            // 生成L2CAP层表格
            let bleL2capTable = '';
            if (l2cap) {
                bleL2capTable = generateTable(l2cap, 'L2CAP 层');
            }
            
            // 生成SMP层表格
            let bleSmTable = '';
            if (sm) {
                bleSmTable = generateTable(sm, 'SMP 层');
            }
            
            // 生成ATT层表格
            let bleAttTable = '';
            if (att) {
                bleAttTable = generateTable(att, 'ATT 层');
            }
            
            // 生成基础BLE数据包表格
            let bleBasicPacketTable = '';
            if (basic) {
                bleBasicPacketTable = generateTable(basic, 'BLE 基础数据包 层');
            }
            
            // 组合所有BLE相关表格
            bleTable = bleBasicTable + bleLlTable + bleSpecialFormatTable + bleNrfSnifferTable + bleL2capTable + bleSmTable + bleAttTable + bleBasicPacketTable;
        }
        
        // 如果是ICMP协议，生成ICMP层表格
        if (packet.layers?.transport?.type === 'ICMP') {
            const icmpData = { ...packet.layers.transport };
            delete icmpData.type; // 已在标题中显示
            icmpTable = generateTable(icmpData, 'ICMP 层');
        }
        
        // 如果是ICMPv6协议，生成ICMPv6层表格
        if (packet.layers?.transport?.type === 'ICMPv6') {
            const icmpv6Data = { ...packet.layers.transport };
            delete icmpv6Data.type; // 已在标题中显示
            icmpv6Table = generateTable(icmpv6Data, 'ICMPv6 层');
        }
        
        // 如果是IGMP协议，生成IGMP层表格
        if (packet.layers?.transport?.type === 'IGMP') {
            const igmpData = { ...packet.layers.transport };
            delete igmpData.type; // 已在标题中显示
            igmpTable = generateTable(igmpData, 'IGMP 层');
        }
        
        // 如果是LLDP协议，生成LLDP层表格
        if (packet.protocol === 'LLDP') {
            // 注意：我们需要保留tlvList用于generateLldpTable函数内部使用
            // 所以我们不创建新对象，而是直接传递原始network数据
            lldpTable = generateLldpTable(packet.layers.network, 'LLDP 层');
        }
        
        // 生成TCP重组信息表格
        let tcpReassemblyTable = '';
        let httpParsedInfo = '';
        if (packet.tcpReassemblyInfo) {
            const reassemblyInfo = packet.tcpReassemblyInfo;
            
            // 格式化重组后的数据
            let reassembledHexStr = '';
            let reassembledAsciiStr = '';
            
            if (reassemblyInfo.reassembledData && reassemblyInfo.reassembledData.length > 0) {
                // 生成十六进制表示
                reassembledHexStr = reassemblyInfo.reassembledData.map(byte => byte.toString(16).padStart(2, '0')).join(' ');
                // 生成ASCII表示
                reassembledAsciiStr = reassemblyInfo.reassembledData.map(byte => {
                    return (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
                }).join('');
                
                // 尝试解析HTTP协议
                const asciiText = reassembledAsciiStr;
                if (asciiText.startsWith('GET ') || asciiText.startsWith('POST ') || asciiText.startsWith('PUT ') || 
                    asciiText.startsWith('DELETE ') || asciiText.startsWith('HEAD ') || asciiText.startsWith('OPTIONS ') ||
                    asciiText.startsWith('HTTP/')) {
                    
                    // 替换..为换行符，修复显示问题
                    const normalizedText = asciiText.replace(/\.\./g, '\r\n');
                    const lines = normalizedText.split(/\r?\n/);
                    
                    // 解析HTTP请求/响应行
                    let httpLine = lines[0];
                    let headers = [];
                    let body = '';
                    let bodyStartIndex = -1;
                    
                    // 解析头部
                    for (let i = 1; i < lines.length; i++) {
                        const line = lines[i].trim();
                        if (line === '') {
                            bodyStartIndex = i + 1;
                            break;
                        }
                        if (line.includes(':')) {
                            const [name, value] = line.split(':', 2);
                            headers.push({ name: name.trim(), value: value.trim() });
                        }
                    }
                    
                    // 解析请求体
                    if (bodyStartIndex > 0 && bodyStartIndex < lines.length) {
                        body = lines.slice(bodyStartIndex).join('\n');
                    }
                    
                    // 生成HTTP结构化信息
                    httpParsedInfo = '<div style="margin-top: 20px; border-top: 1px solid #eee; padding-top: 20px;">' +
                        '<h4>HTTP解析信息</h4>' +
                        '<table style="width: 100%; border-collapse: collapse; margin-top: 10px; margin-left: 20px;">' +
                            '<tr>' +
                                '<th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd; width: 250px;">属性</th>' +
                                '<th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd;">值</th>' +
                            '</tr>' +
                            '<tr>' +
                                '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">HTTP行</td>' +
                                '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; background-color: #f5f5f5; font-family: monospace;">' + htmlEscape(httpLine) + '</td>' +
                            '</tr>';
                    
                    // 添加请求头
                    if (headers.length > 0) {
                        httpParsedInfo += '<tr>' +
                            '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; vertical-align: top;">请求头</td>' +
                            '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 300px; overflow-y: auto; background-color: #f5f5f5; font-family: monospace;">';
                        
                        headers.forEach(header => {
                            httpParsedInfo += htmlEscape(header.name) + ': ' + htmlEscape(header.value) + '\n';
                        });
                        
                        httpParsedInfo += '</td></tr>';
                    }
                    
                    // 添加请求体
                    if (body) {
                        httpParsedInfo += '<tr>' +
                            '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; vertical-align: top;">请求体</td>' +
                            '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 300px; overflow-y: auto; background-color: #f5f5f5; font-family: monospace;">' + htmlEscape(body) + '</td>' +
                            '</tr>';
                    }
                    
                    httpParsedInfo += '</table></div>';
                }
            }
            
            tcpReassemblyTable = '<div style="margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px;">' +
                '<h4>TCP重组信息</h4>' +
                '<table style="width: 100%; border-collapse: collapse; margin-top: 10px; margin-left: 20px;">' +
                    '<tr>' +
                        '<th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd; width: 250px;">属性</th>' +
                        '<th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd;">值</th>' +
                    '</tr>' +
                    '<tr>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">流ID</td>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' + reassemblyInfo.streamId + '</td>' +
                    '</tr>' +
                    '<tr>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">方向</td>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' + (reassemblyInfo.direction === 'clientToServer' ? '客户端 → 服务器' : '服务器 → 客户端') + '</td>' +
                    '</tr>' +
                    '<tr>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">重组后数据长度</td>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' + reassemblyInfo.reassembledDataLength + ' bytes</td>' +
                    '</tr>' +
                    '<tr>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">相关数据包数量</td>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">' + reassemblyInfo.relatedPackets + '</td>' +
                    '</tr>' +
                    '<tr>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; vertical-align: top;">重组后数据（十六进制）</td>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 300px; overflow-y: auto; background-color: #f5f5f5; font-family: monospace;">' +
                            (reassembledHexStr || '无重组数据') +
                        '</td>' +
                    '</tr>' +
                    '<tr>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; vertical-align: top;">重组后数据（ASCII）</td>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 300px; overflow-y: auto; background-color: #f5f5f5; font-family: monospace;">' +
                            (reassembledAsciiStr || '无重组数据') +
                        '</td>' +
                    '</tr>' +
                '</table>' +
            '</div>';
        }
        
        detailsDiv.innerHTML = navigationButtons + '<h3>数据包 ' + (packetIndex + 1) + ' 详情</h3>' +
        '<div style="margin-top: 20px;">' +
            '<h4>基本信息</h4>' +
            '<table style="width: 100%; border-collapse: collapse; margin-top: 10px; margin-left: 20px;">' +
                '<tr>' +
                    '<th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd; width: 250px;">属性</th>' +
                    '<th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd;">值</th>' +
                '</tr>' +
                '<tr>' +
                    '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">唯一ID</td>' +
                    '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' + packet.uniqueId + '</td>' +
                '</tr>' +
                '<tr>' +
                    '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">时间</td>' +
                    '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' + packet.packetTime + '</td>' +
                '</tr>' +
                '<tr>' +
                    '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">捕获长度</td>' +
                    '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' + packet.capturedLen + ' bytes</td>' +
                '</tr>' +
                '<tr>' +
                    '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">原始长度</td>' +
                    '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' + packet.packetLen + ' bytes</td>' +
                '</tr>' +
                '<tr>' +
                    '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">协议</td>' +
                    '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-width: 400px; overflow-x: auto;">' + (packet.protocolChain || packet.protocol) + '</td>' +
                '</tr>' +
                '<tr>' +
                    '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">流ID</td>' +
                    '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' +
                        (packet.streamId ? 
                            '<a href="javascript:void(0);" onclick="showFlowDetails(' + packet.streamId + ');" style="color: #3498db; text-decoration: underline;">流 ' + packet.streamId + '</a>' : 
                            '无') +
                    '</td>' +
                '</tr>' +
                '<tr>' +
                '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">源MAC地址</td>' +
                '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' + (packet.layers?.link?.srcMac || '-') + '</td>' +
                '</tr>' +
                '<tr>' +
                '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">目标MAC地址</td>' +
                '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' + (packet.layers?.link?.dstMac || '-') + '</td>' +
                '</tr>' +
                '<tr>' +
                '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">信息</td>' +
                '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">' + htmlEscape(packet.info) + '</td>' +
                '</tr>' +
            '</table>' +
        '</div>' +
        '<div style="margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px;">' +
            ethernetTable +
            networkTable +
            transportTable +
            icmpTable +
            icmpv6Table +
            igmpTable +
            applicationTable +
            smtpTable +
            httpTable +
            dnsTable +
            ssdpTable +
            mdnsTable +
            nbnsTable +
            llmnrTable +
            browserTable +
            usbTable +
            hciUsbTable +
            lldpTable +
            bleTable +
        '</div>' +
            tcpReassemblyTable +
            httpParsedInfo +
        '<div style="margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px;">' +
            '<h4>十六进制数据</h4>' +
            '<div class="packet-hex">' + htmlEscape(hexData) + '</div>' +
        '</div>';
        
        // 为TCP重组信息中的相关数据包添加点击事件
        if (packet.tcpReassemblyInfo) {
            const relatedPacketsCells = detailsDiv.querySelectorAll('td');
            relatedPacketsCells.forEach(cell => {
                if (cell.textContent.includes(',')) {
                    const content = cell.textContent;
                    const packetIds = content.split(',').map(id => id.trim()).filter(id => !isNaN(id));
                    if (packetIds.length > 0) {
                        // 创建新的HTML内容，将数据包ID转换为可点击的链接
                        let newContent = content;
                        packetIds.forEach(packetId => {
                            // 直接传递uniqueId，让showPacketDetailsByUniqueId函数处理
                            newContent = newContent.replace(packetId, `<a href="javascript:void(0);" onclick="showPacketDetailsByUniqueId(${packetId});" style="color: #3498db; text-decoration: underline; cursor: pointer;">${packetId}</a>`);
                        });
                        cell.innerHTML = newContent;
                    }
                }
            });
        }
}

// 根据数据包唯一ID显示详情
function showPacketDetailsByUniqueId(uniqueId) {
    // 直接根据唯一ID查找数据包，不依赖索引
    let packet = null;
    let packetIndex = -1;
    
    // 先在currentPackets中查找
    packetIndex = currentPackets.findIndex(p => p.uniqueId === uniqueId);
    if (packetIndex !== -1) {
        packet = currentPackets[packetIndex];
    } else {
        // 再在originalPackets中查找
        const originalIndex = originalPackets.findIndex(p => p.uniqueId === uniqueId);
        if (originalIndex !== -1) {
            packet = originalPackets[originalIndex];
            // 更新currentPackets，确保包含该数据包
            if (!currentPackets.includes(packet)) {
                currentPackets.push(packet);
                packetIndex = currentPackets.length - 1;
            }
        }
    }
    
    if (packet && packetIndex !== -1) {
        // 保存当前数据包索引
        currentPacketIndex = packetIndex;
        
        // 切换到详情标签
        switchTab('details');
        
        const detailsDiv = document.getElementById('packetDetails');
        const hexData = PcapngParser.packetToHex(packet.data);
        
        // 生成导航按钮
        let navigationButtons = `<div style="margin-bottom: 20px; display: flex; gap: 10px; align-items: center;">
            <button id="prevPacketBtn" onclick="navigatePacket(-1)" ${currentPacketIndex === 0 ? 'disabled' : ''} 
                    style="padding: 8px 16px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; ">
                上一个数据包
            </button>
            <button id="nextPacketBtn" onclick="navigatePacket(1)" ${currentPacketIndex === currentPackets.length - 1 ? 'disabled' : ''} 
                    style="padding: 8px 16px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; ">
                下一个数据包
            </button>
            <span style="margin-left: 20px; font-weight: bold;">数据包 ${currentPacketIndex + 1} / ${currentPackets.length}</span>
        </div>`;
        
        // 生成各层协议表格
            const ethernetTable = generateTable(packet.layers?.link, '数据链路层 (以太网)');
            // 生成网络层表格，但LLDP协议除外（LLDP有专门的表格生成函数）
            let networkTable = '';
            if (packet.protocol !== 'LLDP') {
                networkTable = generateTable(packet.layers?.network, '网络层');
            }
            const transportTable = generateTable(packet.layers?.transport, '传输层');
            
            // 生成应用层协议表格
            let applicationTable = '';
            let smtpTable = '';
            let httpTable = '';
            let dnsTable = '';
            let icmpTable = '';
            let icmpv6Table = '';
            let igmpTable = '';
            let ssdpTable = '';
            let mdnsTable = '';
            let nbnsTable = '';
            let llmnrTable = '';
            let browserTable = '';
            let usbTable = '';
            let hciUsbTable = '';
            let lldpTable = '';
            let bleTable = '';
            
            if (packet.layers?.application) {
                // 创建应用层协议数据的副本，移除特定协议信息字段
                const appData = { ...packet.layers.application };
                const smtpInfo = appData.smtpInfo;
                const httpInfo = appData.httpInfo;
                const dnsInfo = appData.dnsInfo;
                const ssdpInfo = appData.ssdpInfo;
                const mdnsInfo = appData.mdnsInfo;
                const nbnsInfo = appData.nbnsInfo;
                const llmnrInfo = appData.llmnrInfo;
                const browserInfo = appData.browserInfo;
                
                delete appData.data; // 移除原始数据
                delete appData.smtpInfo; // 移除smtpInfo，单独处理
                delete appData.httpInfo; // 移除httpInfo，单独处理
                delete appData.dnsInfo; // 移除dnsInfo，单独处理
                delete appData.ssdpInfo; // 移除ssdpInfo，单独处理
                delete appData.mdnsInfo; // 移除mdnsInfo，单独处理
                delete appData.nbnsInfo; // 移除nbnsInfo，单独处理
                delete appData.llmnrInfo; // 移除llmnrInfo，单独处理
                delete appData.browserInfo; // 移除browserInfo，单独处理
                
                applicationTable = generateTable(appData, '应用层');
                
                // 如果是SMTP协议，生成SMTP层表格
                if (smtpInfo && packet.layers.application.protocol === 'SMTP') {
                    smtpTable = generateTable(smtpInfo, 'SMTP 层');
                }
                
                // 如果是HTTP协议，生成HTTP层表格
                if (httpInfo && packet.layers.application.protocol === 'HTTP') {
                    httpTable = generateTable(httpInfo, 'HTTP 层');
                }
                
                // 如果是DNS协议，生成DNS层表格
            if (dnsInfo && packet.layers.application.protocol === 'DNS') {
                // 处理DNS解析结果，添加解析后的域名和IP地址
                const dnsDisplayInfo = { ...dnsInfo };
                
                // DNS记录类型映射
                const dnsTypeMap = {
                    1: 'A (Address)',
                    28: 'AAAA (IPv6 Address)',
                    5: 'CNAME (Canonical Name)',
                    15: 'MX (Mail Exchange)',
                    16: 'TXT (Text)',
                    2: 'NS (Name Server)',
                    6: 'SOA (Start of Authority)',
                    12: 'PTR (Pointer)',
                    33: 'SRV (Service Location)'
                };
                
                // DNS类别映射
                const dnsClassMap = {
                    1: 'IN (Internet)',
                    2: 'CS (CSNET)',
                    3: 'CH (CHAOS)',
                    4: 'HS (Hesiod)'
                };
                
                // 处理DNS查询，转换为可读字符串
                if (dnsDisplayInfo.queries && dnsDisplayInfo.queries.length > 0) {
                    dnsDisplayInfo.queries = dnsDisplayInfo.queries.map((query, index) => 
                        `${index + 1}. ${query.name} (Type: ${dnsTypeMap[query.type] || query.type}, Class: ${dnsClassMap[query.class] || query.class})`
                    ).join('\n');
                }
                
                // 处理DNS回答记录
                if (dnsDisplayInfo.answers && dnsDisplayInfo.answers.length > 0) {
                    dnsDisplayInfo.answers = dnsDisplayInfo.answers.map((answer, index) => {
                        let answerStr = `${index + 1}. ${answer.name} (Type: ${dnsTypeMap[answer.type] || answer.type}, Class: ${dnsClassMap[answer.class] || answer.class}`;
                        if (answer.ttl) {
                            answerStr += `, TTL: ${answer.ttl}`;
                        }
                        if (answer.data) {
                            answerStr += `, Data: ${answer.data}`;
                        }
                        return answerStr + ')';
                    }).join('\n');
                }
                
                // 处理DNS权威记录
                if (dnsDisplayInfo.authorities && dnsDisplayInfo.authorities.length > 0) {
                    dnsDisplayInfo.authorities = dnsDisplayInfo.authorities.map((record, index) => {
                        let recordStr = `${index + 1}. ${record.name} (Type: ${dnsTypeMap[record.type] || record.type}, Class: ${dnsClassMap[record.class] || record.class}`;
                        if (record.ttl) {
                            recordStr += `, TTL: ${record.ttl}`;
                        }
                        if (record.data) {
                            recordStr += `, Data: ${record.data}`;
                        }
                        return recordStr + ')';
                    }).join('\n');
                }
                
                // 处理DNS附加记录
                if (dnsDisplayInfo.additionals && dnsDisplayInfo.additionals.length > 0) {
                    dnsDisplayInfo.additionals = dnsDisplayInfo.additionals.map((record, index) => {
                        let recordStr = `${index + 1}. ${record.name} (Type: ${dnsTypeMap[record.type] || record.type}, Class: ${dnsClassMap[record.class] || record.class}`;
                        if (record.ttl) {
                            recordStr += `, TTL: ${record.ttl}`;
                        }
                        if (record.data) {
                            recordStr += `, Data: ${record.data}`;
                        }
                        return recordStr + ')';
                    }).join('\n');
                }
                
                // 如果有解析结果，添加到显示信息中
                if (dnsDisplayInfo.resolvedDomains && dnsDisplayInfo.resolvedDomains.length > 0) {
                    dnsDisplayInfo.resolvedDomains = dnsDisplayInfo.resolvedDomains.map((item, index) => 
                        `${index + 1}. ${item.domain} → ${item.ip} (${item.type})`
                    ).join('\n');
                }
                
                dnsTable = generateTable(dnsDisplayInfo, 'DNS 层');
            }
                
                // 如果是SSDP协议，生成SSDP层表格
                if (ssdpInfo && packet.layers.application.protocol === 'SSDP') {
                    ssdpTable = generateTable(ssdpInfo, 'SSDP 层');
                }
                
                // 如果是MDNS协议，生成MDNS层表格
                if (mdnsInfo && packet.layers.application.protocol === 'MDNS') {
                    const mdnsDisplayInfo = { ...mdnsInfo };
                    
                    // DNS记录类型映射
                    const dnsTypeMap = {
                        1: 'A (Address)',
                        28: 'AAAA (IPv6 Address)',
                        5: 'CNAME (Canonical Name)',
                        15: 'MX (Mail Exchange)',
                        16: 'TXT (Text)',
                        2: 'NS (Name Server)',
                        6: 'SOA (Start of Authority)',
                        12: 'PTR (Pointer)',
                        33: 'SRV (Service Location)'
                    };
                    
                    // DNS类别映射
                    const dnsClassMap = {
                        1: 'IN (Internet)',
                        2: 'CS (CSNET)',
                        3: 'CH (CHAOS)',
                        4: 'HS (Hesiod)'
                    };
                    
                    // 处理MDNS查询，转换为可读字符串
                    if (mdnsDisplayInfo.queries && mdnsDisplayInfo.queries.length > 0) {
                        mdnsDisplayInfo.queries = mdnsDisplayInfo.queries.map((query, index) => 
                            `${index + 1}. ${query.name} (Type: ${dnsTypeMap[query.type] || query.type}, Class: ${dnsClassMap[query.class] || query.class})`
                        ).join('\n');
                    }
                    
                    // 处理MDNS回答记录
                    if (mdnsDisplayInfo.answers && mdnsDisplayInfo.answers.length > 0) {
                        mdnsDisplayInfo.answers = mdnsDisplayInfo.answers.map((answer, index) => {
                            let answerStr = `${index + 1}. ${answer.name} (Type: ${dnsTypeMap[answer.type] || answer.type}, Class: ${dnsClassMap[answer.class] || answer.class}`;
                            if (answer.ttl) {
                                answerStr += `, TTL: ${answer.ttl}`;
                            }
                            if (answer.data) {
                                answerStr += `, Data: ${answer.data}`;
                            }
                            return answerStr + ')';
                        }).join('\n');
                    }
                    
                    mdnsTable = generateTable(mdnsDisplayInfo, 'MDNS 层');
                }
                
                // 如果是NBNS协议，生成NBNS层表格
                if (nbnsInfo && packet.layers.application.protocol === 'NBNS') {
                    nbnsTable = generateTable(nbnsInfo, 'NBNS 层');
                }
                
                // 如果是LLMNR协议，生成LLMNR层表格
                if (llmnrInfo && packet.layers.application.protocol === 'LLMNR') {
                    // 处理LLMNR解析结果，添加解析后的域名和IP地址
                    const llmnrDisplayInfo = { ...llmnrInfo };
                    
                    // DNS记录类型映射
                    const dnsTypeMap = {
                        1: 'A (Address)',
                        28: 'AAAA (IPv6 Address)',
                        5: 'CNAME (Canonical Name)',
                        15: 'MX (Mail Exchange)',
                        16: 'TXT (Text)',
                        2: 'NS (Name Server)',
                        6: 'SOA (Start of Authority)',
                        12: 'PTR (Pointer)',
                        33: 'SRV (Service Location)'
                    };
                    
                    // DNS类别映射
                    const dnsClassMap = {
                        1: 'IN (Internet)',
                        2: 'CS (CSNET)',
                        3: 'CH (CHAOS)',
                        4: 'HS (Hesiod)'
                    };
                    
                    // 处理LLMNR查询，转换为可读字符串
                    if (llmnrDisplayInfo.queries && llmnrDisplayInfo.queries.length > 0) {
                        llmnrDisplayInfo.queries = llmnrDisplayInfo.queries.map((query, index) => 
                            `${index + 1}. ${query.name} (Type: ${dnsTypeMap[query.type] || query.type}, Class: ${dnsClassMap[query.class] || query.class})`
                        ).join('\n');
                    }
                    
                    // 处理LLMNR回答记录
                    if (llmnrDisplayInfo.answers && llmnrDisplayInfo.answers.length > 0) {
                        llmnrDisplayInfo.answers = llmnrDisplayInfo.answers.map((answer, index) => {
                            let answerStr = `${index + 1}. ${answer.name} (Type: ${dnsTypeMap[answer.type] || answer.type}, Class: ${dnsClassMap[answer.class] || answer.class}`;
                            if (answer.ttl) {
                                answerStr += `, TTL: ${answer.ttl}`;
                            }
                            if (answer.data) {
                                answerStr += `, Data: ${answer.data}`;
                            }
                            return answerStr + ')';
                        }).join('\n');
                    }
                    
                    // 如果有解析结果，添加到显示信息中
                    if (llmnrDisplayInfo.resolvedDomains && llmnrDisplayInfo.resolvedDomains.length > 0) {
                        llmnrDisplayInfo.resolvedDomains = llmnrDisplayInfo.resolvedDomains.map((item, index) => 
                            `${index + 1}. ${item.domain} → ${item.ip} (${item.type})`
                        ).join('\n');
                    }
                    
                    llmnrTable = generateTable(llmnrDisplayInfo, 'LLMNR 层');
                }
                
                // 如果是BROWSER协议，生成BROWSER层表格
                if (browserInfo && packet.layers.application.protocol === 'BROWSER') {
                    browserTable = generateTable(browserInfo, 'BROWSER 层');
                }
            } else {
                applicationTable = '<h4>应用层</h4><p style="color: #666; margin-left: 20px;">未解析</p>';
            }
            
            // 处理USB协议
            if (packet.protocol === 'USB' && packet.layers?.link?.type === 'USB') {
                // 生成详细的USB协议分析
                usbTable = generateDetailedUsbInfo(packet, 'USB 层');
            }
            
            // 处理HCI_USB协议
            if (packet.protocol === 'HCI_USB' && packet.layers?.link?.type === 'USB') {
                const hciUsbData = { ...packet.layers.link };
                delete hciUsbData.type; // 已在标题中显示
                delete hciUsbData.linkType; // 已在标题中显示
                hciUsbTable = generateTable(hciUsbData, 'HCI_USB 层');
            }
            
            // 处理BLE协议，生成BLE层表格
            if (packet.protocol.startsWith('BLE') && packet.layers?.link?.type === 'BLE') {
                const bleData = { ...packet.layers.link };
                
                // 移除已经单独处理的子协议，避免重复显示
                const { l2cap, sm, att, basic, specialFormat, nrfSnifferHeader, ll, ...remainingBleData } = bleData;
                
                // 生成基本BLE信息表格
                let bleBasicTable = '<h4>BLE 层</h4>';
                if (Object.keys(remainingBleData).length > 0) {
                    bleBasicTable = generateTable(remainingBleData, 'BLE 层');
                }
                
                // 生成LL层信息表格
                let bleLlTable = '';
                if (ll) {
                    bleLlTable = generateTable(ll, 'BLE Link Layer (LL) 层');
                }
                
                // 生成特殊格式表格
                let bleSpecialFormatTable = '';
                if (specialFormat) {
                    bleSpecialFormatTable = generateTable(specialFormat, 'BLE 特殊格式 层');
                }
                
                // 生成nRF Sniffer头部表格
                let bleNrfSnifferTable = '';
                if (nrfSnifferHeader) {
                    bleNrfSnifferTable = generateTable(nrfSnifferHeader, 'nRF Sniffer 头部 层');
                }
                
                // 生成L2CAP层表格
                let bleL2capTable = '';
                if (l2cap) {
                    bleL2capTable = generateTable(l2cap, 'L2CAP 层');
                }
                
                // 生成SMP层表格
                let bleSmTable = '';
                if (sm) {
                    bleSmTable = generateTable(sm, 'SMP 层');
                }
                
                // 生成ATT层表格
                let bleAttTable = '';
                if (att) {
                    bleAttTable = generateTable(att, 'ATT 层');
                }
                
                // 生成基础BLE数据包表格
                let bleBasicPacketTable = '';
                if (basic) {
                    bleBasicPacketTable = generateTable(basic, 'BLE 基础数据包 层');
                }
                
                // 组合所有BLE相关表格
                bleTable = bleBasicTable + bleLlTable + bleSpecialFormatTable + bleNrfSnifferTable + bleL2capTable + bleSmTable + bleAttTable + bleBasicPacketTable;
            }
            
            // 如果是ICMP协议，生成ICMP层表格
            if (packet.layers?.transport?.type === 'ICMP') {
                const icmpData = { ...packet.layers.transport };
                delete icmpData.type; // 已在标题中显示
                icmpTable = generateTable(icmpData, 'ICMP 层');
            }
            
            // 如果是ICMPv6协议，生成ICMPv6层表格
            if (packet.layers?.transport?.type === 'ICMPv6') {
                const icmpv6Data = { ...packet.layers.transport };
                delete icmpv6Data.type; // 已在标题中显示
                icmpv6Table = generateTable(icmpv6Data, 'ICMPv6 层');
            }
            
            // 如果是IGMP协议，生成IGMP层表格
            if (packet.layers?.transport?.type === 'IGMP') {
                const igmpData = { ...packet.layers.transport };
                delete igmpData.type; // 已在标题中显示
                igmpTable = generateTable(igmpData, 'IGMP 层');
            }
            
            // 如果是LLDP协议，生成LLDP层表格
            if (packet.protocol === 'LLDP') {
                // 注意：我们需要保留tlvList用于generateLldpTable函数内部使用
                // 所以我们不创建新对象，而是直接传递原始network数据
                lldpTable = generateLldpTable(packet.layers.network, 'LLDP 层');
            }
            
            // 生成TCP重组信息表格
            let tcpReassemblyTable = '';
            let httpParsedInfo = '';
            if (packet.tcpReassemblyInfo) {
                const reassemblyInfo = packet.tcpReassemblyInfo;
                
                // 格式化重组后的数据
                let reassembledHexStr = '';
                let reassembledAsciiStr = '';
                if (reassemblyInfo.reassembledData && reassemblyInfo.reassembledData.length > 0) {
                    // 生成十六进制表示
                    reassembledHexStr = reassemblyInfo.reassembledData.map(byte => byte.toString(16).padStart(2, '0')).join(' ');
                    // 生成ASCII表示
                    reassembledAsciiStr = reassemblyInfo.reassembledData.map(byte => {
                        return (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
                    }).join('');
                    
                    // 尝试解析HTTP协议
                    const asciiText = reassembledAsciiStr;
                    if (asciiText.startsWith('GET ') || asciiText.startsWith('POST ') || asciiText.startsWith('PUT ') || 
                        asciiText.startsWith('DELETE ') || asciiText.startsWith('HEAD ') || asciiText.startsWith('OPTIONS ') ||
                        asciiText.startsWith('HTTP/')) {
                        
                        // 替换..为换行符，修复显示问题
                        const normalizedText = asciiText.replace(/\.\./g, '\r\n');
                        const lines = normalizedText.split(/\r?\n/);
                        
                        // 解析HTTP请求/响应行
                        let httpLine = lines[0];
                        let headers = [];
                        let body = '';
                        let bodyStartIndex = -1;
                        
                        // 解析头部
                        for (let i = 1; i < lines.length; i++) {
                            const line = lines[i].trim();
                            if (line === '') {
                                bodyStartIndex = i + 1;
                                break;
                            }
                            if (line.includes(':')) {
                                const [name, value] = line.split(':', 2);
                                headers.push({ name: name.trim(), value: value.trim() });
                            }
                        }
                        
                        // 解析请求体
                        if (bodyStartIndex > 0 && bodyStartIndex < lines.length) {
                            body = lines.slice(bodyStartIndex).join('\n');
                        }
                        
                        // 生成HTTP结构化信息
                        httpParsedInfo = '<div style="margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px;">' +
                            '<h4>HTTP解析信息</h4>' +
                            '<table style="width: 100%; border-collapse: collapse; margin-top: 10px; margin-left: 20px;">' +
                                '<tr>' +
                                    '<th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd; width: 250px;">属性</th>' +
                                    '<th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd;">值</th>' +
                                '</tr>' +
                                '<tr>' +
                                    '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">HTTP行</td>' +
                                    '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; background-color: #f5f5f5; font-family: monospace;">' + htmlEscape(httpLine) + '</td>' +
                                '</tr>';
                        
                        // 添加请求头
                        if (headers.length > 0) {
                            httpParsedInfo += '<tr>' +
                                '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; vertical-align: top;">请求头</td>' +
                                '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 300px; overflow-y: auto; background-color: #f5f5f5; font-family: monospace;">';
                        
                            headers.forEach(header => {
                                httpParsedInfo += htmlEscape(header.name) + ': ' + htmlEscape(header.value) + '\n';
                            });
                        
                            httpParsedInfo += '</td></tr>';
                        }
                        
                        // 添加请求体
                        if (body) {
                            httpParsedInfo += '<tr>' +
                                '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; vertical-align: top;">请求体</td>' +
                                '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 300px; overflow-y: auto; background-color: #f5f5f5; font-family: monospace;">' + htmlEscape(body) + '</td>' +
                                '</tr>';
                        }
                        
                        httpParsedInfo += '</table></div>';
                    }
                }
                
                tcpReassemblyTable = '<div style="margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px;">' +
                    '<h4>TCP重组信息</h4>' +
                    '<table style="width: 100%; border-collapse: collapse; margin-top: 10px; margin-left: 20px;">' +
                        '<tr>' +
                            '<th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd; width: 250px;">属性</th>' +
                            '<th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd;">值</th>' +
                        '</tr>' +
                        '<tr>' +
                            '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">流ID</td>' +
                            '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' + reassemblyInfo.streamId + '</td>' +
                        '</tr>' +
                        '<tr>' +
                            '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">方向</td>' +
                            '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' + (reassemblyInfo.direction === 'clientToServer' ? '客户端 → 服务器' : '服务器 → 客户端') + '</td>' +
                        '</tr>' +
                        '<tr>' +
                            '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">重组后数据长度</td>' +
                            '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' + reassemblyInfo.reassembledDataLength + ' bytes</td>' +
                        '</tr>' +
                        '<tr>' +
                            '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">相关数据包</td>' +
                            '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">' + reassemblyInfo.relatedPackets.join(', ') + '</td>' +
                        '</tr>' +
                        '<tr>' +
                            '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; vertical-align: top;">重组后数据（十六进制）</td>' +
                            '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 300px; overflow-y: auto; background-color: #f5f5f5; font-family: monospace;">' +
                                (reassembledHexStr || '无重组数据') +
                            '</td>' +
                        '</tr>' +
                        '<tr>' +
                            '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; vertical-align: top;">重组后数据（ASCII）</td>' +
                            '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 300px; overflow-y: auto; background-color: #f5f5f5; font-family: monospace;">' +
                                (reassembledAsciiStr || '无重组数据') +
                            '</td>' +
                        '</tr>' +
                    '</table>' +
                '</div>';
            }
            
            detailsDiv.innerHTML = navigationButtons + '<h3>数据包 ' + (packetIndex + 1) + ' 详情</h3>' +
            '<div style="margin-top: 20px;">' +
                '<h4>基本信息</h4>' +
                '<table style="width: 100%; border-collapse: collapse; margin-top: 10px; margin-left: 20px;">' +
                    '<tr>' +
                        '<th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd; width: 250px;">属性</th>' +
                        '<th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd;">值</th>' +
                    '</tr>' +
                    '<tr>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">唯一ID</td>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' + packet.uniqueId + '</td>' +
                    '</tr>' +
                    '<tr>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">时间</td>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' + packet.packetTime + '</td>' +
                    '</tr>' +
                    '<tr>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">捕获长度</td>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' + packet.capturedLen + ' bytes</td>' +
                    '</tr>' +
                    '<tr>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">原始长度</td>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' + packet.packetLen + ' bytes</td>' +
                    '</tr>' +
                    '<tr>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">协议</td>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-width: 400px; overflow-x: auto;">' + (packet.protocolChain || packet.protocol) + '</td>' +
                    '</tr>' +
                    '<tr>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">流ID</td>' +
                        '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' +
                            (packet.streamId ? 
                                '<a href="javascript:void(0);" onclick="showFlowDetails(' + packet.streamId + ');" style="color: #3498db; text-decoration: underline;">流 ' + packet.streamId + '</a>' : 
                                '无') +
                        '</td>' +
                    '</tr>' +
                    '<tr>' +
                    '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">源MAC地址</td>' +
                    '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' + (packet.layers?.link?.srcMac || '-') + '</td>' +
                    '</tr>' +
                    '<tr>' +
                    '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">目标MAC地址</td>' +
                    '<td style="padding: 8px; border: 1px solid #ddd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-family: Arial, sans-serif;">' + (packet.layers?.link?.dstMac || '-') + '</td>' +
                    '</tr>' +
                    '<tr>' +
                    '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">信息</td>' +
                    '<td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto;">' + htmlEscape(packet.info) + '</td>' +
                    '</tr>' +
                '</table>' +
            '</div>' +
            '<div style="margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px;">' +
                ethernetTable +
                networkTable +
                transportTable +
                icmpTable +
                icmpv6Table +
                igmpTable +
                applicationTable +
                smtpTable +
                httpTable +
                dnsTable +
                ssdpTable +
                mdnsTable +
                nbnsTable +
                llmnrTable +
                browserTable +
                usbTable +
                hciUsbTable +
                lldpTable +
                bleTable +
            '</div>' +
                tcpReassemblyTable +
                httpParsedInfo +
            '<div style="margin-top: 30px; border-top: 1px solid #eee; padding-top: 20px;">' +
                '<h4>十六进制数据</h4>' +
                '<div class="packet-hex">' + htmlEscape(hexData) + '</div>' +
            '</div>';
            
            // 为TCP重组信息中的相关数据包添加点击事件
            if (packet.tcpReassemblyInfo) {
                const relatedPacketsCells = detailsDiv.querySelectorAll('td');
                relatedPacketsCells.forEach(cell => {
                    if (cell.textContent.includes(',')) {
                        const content = cell.textContent;
                        const packetIds = content.split(',').map(id => id.trim()).filter(id => !isNaN(id));
                        if (packetIds.length > 0) {
                            // 创建新的HTML内容，将数据包ID转换为可点击的链接
                            let newContent = content;
                            packetIds.forEach(packetId => {
                                // 直接传递uniqueId，让showPacketDetailsByUniqueId函数处理
                                newContent = newContent.replace(packetId, `<a href="javascript:void(0);" onclick="showPacketDetailsByUniqueId(${packetId});" style="color: #3498db; text-decoration: underline; cursor: pointer;">${packetId}</a>`);
                            });
                            cell.innerHTML = newContent;
                        }
                    }
                });
            }
    }
}

// 显示上一个数据包
function showPreviousPacket() {
    if (currentPacketIndex > 0) {
        showPacketDetails(currentPacketIndex - 1);
    }
}

// 显示下一个数据包
function showNextPacket() {
    if (currentPacketIndex < currentPackets.length - 1) {
        showPacketDetails(currentPacketIndex + 1);
    }
}

// 导航数据包函数
function navigatePacket(direction) {
    if (direction === -1) {
        // 上一个数据包
        showPreviousPacket();
    } else if (direction === 1) {
        // 下一个数据包
        showNextPacket();
    }
}

// 生成详细的USB协议信息
function generateDetailedUsbInfo(packet, title) {
    let html = '';
    try {
        const usbData = { ...(packet.layers?.link || {}) };
        const hexData = packet.data ? PcapngParser.packetToHex(packet.data) : '';
        
        // 检查packet.data是否存在
        if (!packet.data) {
            html = `<h4>${title}</h4>`;
            html += `<p style="color: red;">错误：数据包数据不存在</p>`;
            return html;
        }
        
        // 安全的数组访问函数 - 定义在使用之前
        const safeByte = (index, defaultValue = 0) => {
            return packet.data[index] !== undefined ? packet.data[index] : defaultValue;
        };
        
        // 安全的数组切片函数 - 定义在使用之前
        const safeSlice = (start, end, defaultValue = 0) => {
            const result = [];
            for (let i = start; i < end; i++) {
                result.push(safeByte(i, defaultValue));
            }
            return result;
        };
        
        // 检查是否为HID设备 - 使用usbData.isHidDevice字段，该字段由解析器基于接口描述符和端点信息设置
        const isHidDevice = usbData.isHidDevice || 
            (usbData.transferType && usbData.transferType.includes('INTERRUPT')) || 
            (usbData.urbFunction && usbData.urbFunction.includes('INTERRUPT')) ||
            (usbData.urbFunction && usbData.urbFunction === 'URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER') ||
            (usbData.dataLength && usbData.dataLength === 8);
        
        html = `<h4>${title}</h4>`;
    

    

    
    // 3. 详细解析过程 - 已隐藏
    // 重新声明headerLength变量，因为它在注释块内被定义但在外部被使用
    const headerLength = (safeByte(1) << 8 | safeByte(0));
    /*
    html += `<div style="margin-top: 15px; margin-left: 20px;">
                <h5>3. 详细解析过程</h5>`;
    
    // 3.A USBPcap伪头部分析
    html += `<div style="margin-top: 10px;">
                <h6>A. USBPcap 伪头部（前${safeByte(0) === 0x1b ? '27' : '18'}字节）</h6>
                <p style="color: #666; margin-bottom: 10px;">这是 USBPcap 驱动程序添加的元数据，不是实际USB数据。</p>
                <table style="width: 100%; border-collapse: collapse; font-family: Arial, sans-serif; font-size: 13px;">
                    <tr>
                        <th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd; width: 200px;">字段</th>
                        <th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd; width: 150px;">字节位置</th>
                        <th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd; width: 150px;">值</th>
                        <th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd;">描述</th>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border: 1px solid #ddd;">传输类型</td>
                        <td style="padding: 8px; border: 1px solid #ddd;">-</td>
                        <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${htmlEscape(usbData.transferType || 'undefined')}</td>
                        <td style="padding: 8px; border: 1px solid #ddd;">用于调试：实际传输类型值</td>
                    </tr>","}}}
                    <tr>
                        <td style="padding: 8px; border: 1px solid #ddd;">URB函数</td>
                        <td style="padding: 8px; border: 1px solid #ddd;">-</td>
                        <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${htmlEscape(usbData.urbFunction || 'undefined')}</td>
                        <td style="padding: 8px; border: 1px solid #ddd;">用于调试：实际URB函数值</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border: 1px solid #ddd;">Is HID Device</td>
                        <td style="padding: 8px; border: 1px solid #ddd;">-</td>
                        <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${isHidDevice ? 'true' : 'false'}</td>
                        <td style="padding: 8px; border: 1px solid #ddd;">用于调试：HID设备判断结果</td>
                    </tr>`;
    
    // 计算伪头部长度
    const headerLength = (safeByte(1) << 8 | safeByte(0));
    
    // 伪头部长度
    html += `<tr>
                <td style="padding: 8px; border: 1px solid #ddd;">USBPcap 伪头部长度</td>
                <td style="padding: 8px; border: 1px solid #ddd;">0-1</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${safeSlice(0, 2).map(b => b.toString(16).padStart(2, '0')).join(' ')}</td>
                <td style="padding: 8px; border: 1px solid #ddd;">小端序：0x${headerLength.toString(16).toUpperCase()} = ${headerLength} 字节，${headerLength === 27 ? '固定值 0x1B00 表示27字节头部格式' : headerLength === 28 ? '固定值 0x1C00 表示28字节头部格式' : '未知头部格式'}</td>
            </tr>`;
    
    // IRP ID
    html += `<tr>
                <td style="padding: 8px; border: 1px solid #ddd;">IRP ID</td>
                <td style="padding: 8px; border: 1px solid #ddd;">2-9</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${safeSlice(2, 10).map(b => b.toString(16).padStart(2, '0')).join(' ')}</td>
                <td style="padding: 8px; border: 1px solid #ddd;">Windows I/O 请求包ID，用于跟踪USB请求</td>
            </tr>`;
    
    // USBD状态码
    html += `<tr>
                <td style="padding: 8px; border: 1px solid #ddd;">USBD状态码</td>
                <td style="padding: 8px; border: 1px solid #ddd;">10-13</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${safeSlice(10, 14).map(b => b.toString(16).padStart(2, '0')).join(' ')}</td>
                <td style="padding: 8px; border: 1px solid #ddd;">0x${(safeByte(13) << 24 | safeByte(12) << 16 | safeByte(11) << 8 | safeByte(10)).toString(16).toUpperCase()} = USBD_STATUS_SUCCESS，表示USB操作成功完成</td>
            </tr>`;
    
    // URB功能代码
    html += `<tr>
                <td style="padding: 8px; border: 1px solid #ddd;">URB功能代码</td>
                <td style="padding: 8px; border: 1px solid #ddd;">14-15</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${safeSlice(14, 16).map(b => b.toString(16).padStart(2, '0')).join(' ')}</td>
                <td style="padding: 8px; border: 1px solid #ddd;">0x${(safeByte(15) << 8 | safeByte(14)).toString(16).toUpperCase()} = ${usbData.urbFunction}</td>
            </tr>`;
    
    // IRP信息
    const irpInfo = safeByte(16);
    const endpointAddress = headerLength === 27 || headerLength === 28 ? safeByte(21) : safeByte(19);
    const irpDirectionBit = (irpInfo & 0x01); // IRP方向位，0=主机发起，1=设备发起
    const endpointDirectionBit = (endpointAddress & 0x80) ? 1 : 0; // 端点方向位，0=OUT，1=IN
    const irpDirectionStr = irpDirectionBit === 0 ? 'FDO -> PDO (主机发起)' : 'PDO -> FDO (设备发起)';
    const endpointDirectionStr = endpointDirectionBit === 0 ? 'OUT (主机→设备)' : 'IN (设备→主机)';
    
    html += `<tr>
                <td style="padding: 8px; border: 1px solid #ddd;">IRP信息</td>
                <td style="padding: 8px; border: 1px solid #ddd;">16</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${irpInfo.toString(16).padStart(2, '0')}</td>
                <td style="padding: 8px; border: 1px solid #ddd;">二进制：${irpInfo.toString(2).padStart(8, '0')}<br>
                IRP方向位 = ${irpDirectionBit} → ${irpDirectionStr}<br>
                端点方向位 = ${endpointDirectionBit} → ${endpointDirectionStr}<br>
                IRP方向位和端点方向位${(irpDirectionBit === endpointDirectionBit) ? '一致' : '不一致'}，结合传输类型和数据长度判断最终传输方向</td>
            </tr>`;
    
    // USB总线编号
    if (headerLength === 27 || headerLength === 28) {
        // 27字节或28字节头部格式：USB总线编号（2字节）
        const busIdVal = (safeByte(17) | (safeByte(18) << 8));
        html += `<tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">USB总线编号</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">17-18</td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${safeSlice(17, 19).map(b => b.toString(16).padStart(2, '0')).join(' ')}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">USB总线编号：0x${busIdVal.toString(16).toUpperCase()} = ${busIdVal}</td>
                </tr>`;
        
        // 设备地址（2字节）
        const deviceAddr = (safeByte(19) | (safeByte(20) << 8));
        html += `<tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">设备地址</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">19-20</td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${safeSlice(19, 21).map(b => b.toString(16).padStart(2, '0')).join(' ')}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">设备在总线上的地址：0x${deviceAddr.toString(16).toUpperCase()} = ${deviceAddr}</td>
                </tr>`;
        
        // 端点地址
        html += `<tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">端点地址</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">21</td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${safeByte(21).toString(16).padStart(2, '0')}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">二进制：${safeByte(21).toString(2).padStart(8, '0')}<br>最高位 = ${(safeByte(21) & 0x80) ? '1' : '0'} → Direction: ${(safeByte(21) & 0x80) ? 'IN' : 'OUT'}<br>低4位 = ${(safeByte(21) & 0x0F).toString(2).padStart(4, '0')} → Endpoint number: ${safeByte(21) & 0x0F}</td>
                </tr>`;
        
        // 传输类型
        html += `<tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">传输类型</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">22</td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${safeByte(22).toString(16).padStart(2, '0')}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">0x${safeByte(22).toString(16).toUpperCase()} = ${usbData.transferType}</td>
                </tr>`;
        
        // 数据长度
        html += `<tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">数据长度</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">23-24</td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${safeSlice(23, 25).map(b => b.toString(16).padStart(2, '0')).join(' ')}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">小端序：0x${(safeByte(24) << 8 | safeByte(23)).toString(16).toUpperCase()} = ${usbData.dataLength} 字节</td>
                </tr>`;
    } else {
        // 默认USB总线编号
        html += `<tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">USB总线编号</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">17</td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${safeByte(17).toString(16).padStart(2, '0')}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">USB总线编号：${safeByte(17)}</td>
                </tr>`;
        
        // 默认设备地址
        html += `<tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">设备地址</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">18</td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${safeByte(18).toString(16).padStart(2, '0')}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">设备在总线上的地址：${safeByte(18)}</td>
                </tr>`;
        
        // 默认端点地址
        html += `<tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">端点地址</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">19</td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${safeByte(19).toString(16).padStart(2, '0')}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">二进制：${safeByte(19).toString(2).padStart(8, '0')}<br>最高位 = ${(safeByte(19) & 0x80) ? '1' : '0'} → Direction: ${(safeByte(19) & 0x80) ? 'IN' : 'OUT'}<br>低4位 = ${(safeByte(19) & 0x0F).toString(2).padStart(4, '0')} → Endpoint number: ${safeByte(19) & 0x0F}</td>
                </tr>`;
        
        // 默认传输类型
        html += `<tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">传输类型</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">20</td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${safeByte(20).toString(16).padStart(2, '0')}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">0x${safeByte(20).toString(16).toUpperCase()} = ${usbData.transferType}</td>
                </tr>`;
        
        // 默认数据长度
        html += `<tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">数据长度</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">21-22</td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${safeSlice(21, 23).map(b => b.toString(16).padStart(2, '0')).join(' ')}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">小端序：0x${(safeByte(22) << 8 | safeByte(21)).toString(16).toUpperCase()} = ${usbData.dataLength} 字节</td>
                </tr>`;
    }
    
    // 时间戳或其他
    if (headerLength === 27) {
        // 27字节头部格式：时间戳或其他（4字节，25-28）
        html += `<tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">时间戳或其他</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">25-28</td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${safeSlice(25, 29).map(b => b.toString(16).padStart(2, '0')).join(' ')}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">时间戳或其他辅助信息</td>
                </tr>`;
    } else if (headerLength === 28) {
        // 28字节头部格式：USBD标志或其他（4字节，25-29）
        html += `<tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">USBD标志或其他</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">25-29</td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${safeSlice(25, 30).map(b => b.toString(16).padStart(2, '0')).join(' ')}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">USBD标志或其他辅助信息</td>
                </tr>`;
    } else {
        // 默认：时间戳或其他（4字节，23-26）
        html += `<tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">时间戳或其他</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">23-26</td>
                    <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">${safeSlice(23, 27).map(b => b.toString(16).padStart(2, '0')).join(' ')}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">时间戳或其他辅助信息</td>
                </tr>`;
    }
    
    html += `</table>
            </div>`;
    

    
    // 3.B USB数据分析
    if (isHidDevice) {
        // HID数据分析
        // 数据负载已移至基本USB属性表格，不再单独显示
        
        // 从原始数据包的十六进制字符串中提取数据
        // 首先获取完整的十六进制字符串
        const fullHexStr = PcapngParser.packetToHex(packet.data || new Uint8Array());
        
        // 从十六进制字符串中提取原始字节数据
        let rawData = [];
        const lines = fullHexStr.split('\n');
        for (const line of lines) {
            // 分割行，获取十六进制部分
            const parts = line.split(': ');
            if (parts.length < 2) continue;
            
            const hexPart = parts[1].split('|')[0].trim();
            const hexBytes = hexPart.split(/\s+/).filter(Boolean);
            
            for (const hexByte of hexBytes) {
                if (hexByte.length === 2) {
                    rawData.push(parseInt(hexByte, 16));
                }
            }
        }
        
        // 提取HID数据
        const hidData = rawData.slice(usbData.dataStartOffset, usbData.dataStartOffset + usbData.dataLength);
        
        // 格式化显示数据
        const formattedHidData = hidData.map(b => b.toString(16).padStart(2, '0')).join(' ');
        
        

        

    } else if (usbData.transferType === 'CONTROL') {
        // 控制数据分析
        html += `<div style="margin-top: 10px;">
                    <h6>B. Control 数据</h6>`;
        
        if (usbData.hasSetupPacket && usbData.setupPacket) {
            html += `<table style="width: 100%; border-collapse: collapse; font-family: Arial, sans-serif; font-size: 13px; margin-bottom: 10px;">
                        <tr>
                            <th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd; width: 200px;">字段</th>
                            <th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd; width: 150px;">值</th>
                            <th style="text-align: left; padding: 8px; background-color: #f8f9fa; border: 1px solid #ddd;">描述</th>
                        </tr>
                        <tr>
                            <td style="padding: 8px; border: 1px solid #ddd;">bmRequestType</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">0x${(usbData.setupPacket.bmRequestType || 0).toString(16).padStart(2, '0')}</td>
                            <td style="padding: 8px; border: 1px solid #ddd;">${usbData.setupPacket.direction || '-'} ${usbData.setupPacket.requestType || '-'} ${usbData.setupPacket.recipient || '-'}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; border: 1px solid #ddd;">bRequest</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">0x${(usbData.setupPacket.bRequest || 0).toString(16).padStart(2, '0')}</td>
                            <td style="padding: 8px; border: 1px solid #ddd;">${usbData.setupPacket.requestName || '-'}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; border: 1px solid #ddd;">wValue</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">0x${(usbData.setupPacket.wValue || 0).toString(16).padStart(4, '0')}</td>
                            <td style="padding: 8px; border: 1px solid #ddd;">${usbData.setupPacket.descriptorType ? `Descriptor Type: ${usbData.setupPacket.descriptorType}, Index: ${usbData.setupPacket.descriptorIndex}` : 'Value'}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; border: 1px solid #ddd;">wIndex</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">0x${(usbData.setupPacket.wIndex || 0).toString(16).padStart(4, '0')}</td>
                            <td style="padding: 8px; border: 1px solid #ddd;">索引或端点</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; border: 1px solid #ddd;">wLength</td>
                            <td style="padding: 8px; border: 1px solid #ddd; font-family: 'Courier New', monospace;">0x${(usbData.setupPacket.wLength || 0).toString(16).padStart(4, '0')}</td>
                            <td style="padding: 8px; border: 1px solid #ddd;">数据长度</td>
                        </tr>
                    </table>`;
        }
        
        html += `</div>`;
    } else {
        // 其他类型数据分析
        // 数据负载已移至基本USB属性表格，不再单独显示
    }
    */
    
    // 4. Wireshark的智能推断
    // 确定源地址和目的地址
    let srcAddress, dstAddress;
    // 根据RIP值确定地址方向
    // 当RIP为0时，源地址为host，目标地址为总线.设备.端点
    // 当RIP为1时，源地址为总线.设备.端点，目标地址为host
    let rip = 0;
    // 检查是否有RIP相关信息（IRP方向位）
    if (typeof usbData.irpDirection !== 'undefined') {
        rip = usbData.irpDirection;
    } else {
        // 没有RIP信息时，使用传统方向判断
        rip = (usbData.transferDirection === 'OUT' || usbData.transferDirection === 'SETUP') ? 0 : 1;
    }
    

    
    if (rip === 0) {
        // RIP为0：源地址为host，目标地址为总线.设备.端点
        srcAddress = '主机 (Host)';
        dstAddress = `Bus ${usbData.busId} Device ${usbData.deviceAddress} Endpoint ${usbData.endpointNum}`;
    } else {
        // RIP为1：源地址为总线.设备.端点，目标地址为host
        srcAddress = `Bus ${usbData.busId} Device ${usbData.deviceAddress} Endpoint ${usbData.endpointNum}`;
        dstAddress = '主机 (Host)';
    }
    

    

    
    html += `</div>`;
    
    // 7. 基本USB属性表格
    html += `<div style="margin-top: 15px; margin-left: 20px;">
                `;
    
    // 创建基本USB属性表格数据，包含数据负载
    const basicUsbData = { ...usbData };
    
    // 计算并添加USBD状态码、URB功能代码等属性
    // 注意：headerLength变量已经在USBPcap伪头部分析部分声明过
    const usbdStatus = (safeByte(13) << 24 | safeByte(12) << 16 | safeByte(11) << 8 | safeByte(10));
    const urbFunctionCode = (safeByte(15) << 8 | safeByte(14));
    
    // 添加这些属性到基本USB属性中
    basicUsbData.headerLength = `0x${headerLength.toString(16).toUpperCase()} = ${headerLength} 字节`;
    basicUsbData.usbdStatus = `0x${usbdStatus.toString(16).toUpperCase()} = ${usbdStatus === 0 ? 'USBD_STATUS_SUCCESS (操作成功)' : '未知状态'}`;
    basicUsbData.urbFunctionCode = `0x${urbFunctionCode.toString(16).toUpperCase()} = ${usbData.urbFunction || '未知'}`;
    
    // 添加实际数据负载
    let dataPayload = '';
    if (isHidDevice) {
        // 从原始数据包的十六进制字符串中提取HID数据
        const fullHexStr = PcapngParser.packetToHex(packet.data || new Uint8Array());
        let rawData = [];
        const lines = fullHexStr.split('\n');
        for (const line of lines) {
            const parts = line.split(': ');
            if (parts.length < 2) continue;
            
            const hexPart = parts[1].split('|')[0].trim();
            const hexBytes = hexPart.split(/\s+/).filter(Boolean);
            
            for (const hexByte of hexBytes) {
                if (hexByte.length === 2) {
                    rawData.push(parseInt(hexByte, 16));
                }
            }
        }
        
        // 提取HID数据
        const hidData = rawData.slice(usbData.dataStartOffset, usbData.dataStartOffset + usbData.dataLength);
        dataPayload = hidData.map(b => b.toString(16).padStart(2, '0')).join(' ');
    } else if (usbData.transferType === 'CONTROL') {
        // 控制传输数据负载为空，Setup Packet已在详细解析中显示
        dataPayload = '';
    } else {
        // 其他类型数据分析
        const startOffset = safeByte(0) === 0x1b ? 27 : 18;
        const endOffset = startOffset + (usbData.dataLength || 0);
        dataPayload = safeSlice(startOffset, endOffset).map(b => b.toString(16).padStart(2, '0')).join(' ');
    }
    
    // 添加数据负载到基本属性
    if (dataPayload) {
        basicUsbData.dataPayload = dataPayload;
    }
    
    delete basicUsbData.type; // 已在标题中显示
    delete basicUsbData.linkType; // 已在标题中显示
    delete basicUsbData.setupPacket; // 已在详细解析中显示
    
    html += generateTable(basicUsbData, '');
    
    html += `</div>`;
    
    html += `</div>`;
    
    return html;
} catch (e) {
    console.error('生成USB协议信息时出错:', e);
    return `<h4>${title}</h4><p style="color: red;">错误：生成USB协议信息时出错 - ${e.message}</p>`;
}
}

function downloadHttpResponse(packetIndex) {
    const packet = currentPackets[packetIndex];
    if (!packet || !packet.layers?.application?.protocol === 'HTTP') {
        return;
    }
    
    const httpInfo = packet.layers.application.httpInfo;
    if (!httpInfo || !httpInfo.raw || !httpInfo.statusCode) {
        return;
    }
    
    // 检查是否是响应
    if (!httpInfo.statusCode) {
        return;
    }
    
    // 解析HTTP响应，提取响应体
    const rawResponse = httpInfo.raw;
    const headerEndIndex = rawResponse.indexOf('\r\n\r\n');
    if (headerEndIndex === -1) {
        alert('无法解析HTTP响应头');
        return;
    }
    
    const headers = rawResponse.substring(0, headerEndIndex);
    const body = rawResponse.substring(headerEndIndex + 4);
    
    // 提取文件名
    let filename = 'download';
    const contentDispositionMatch = headers.match(/Content-Disposition:.*filename="([^"]+)"/i);
    if (contentDispositionMatch && contentDispositionMatch[1]) {
        filename = contentDispositionMatch[1];
    } else {
        // 根据Content-Type猜测文件名后缀
        const contentTypeMatch = headers.match(/Content-Type:.*\/(\w+)/i);
        if (contentTypeMatch && contentTypeMatch[1]) {
            filename = `download.${contentTypeMatch[1]}`;
        }
    }
    
    // 处理不同类型的响应体
    let blob;
    if (httpInfo.statusCode === '200') {
        // 对于200响应，尝试解析响应体
        if (headers.includes('Content-Encoding: gzip') || headers.includes('Content-Encoding: deflate')) {
            alert('压缩的响应体暂不支持下载');
            return;
        }
        
        // 检查是否是二进制数据
        if (headers.includes('Content-Type: application/octet-stream') || 
            headers.includes('Content-Type: image/') || 
            headers.includes('Content-Type: application/pdf')) {
            // 二进制数据，需要特殊处理
            // 这里简化处理，实际应该根据原始二进制数据创建Blob
            blob = new Blob([body], { type: httpInfo.contentType || 'application/octet-stream' });
        } else {
            // 文本数据
            blob = new Blob([body], { type: 'text/plain' });
        }
    } else {
        blob = new Blob([body], { type: httpInfo.contentType || 'text/plain' });
    }
    
    // 创建下载链接
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// IP端口统计排序函数
let currentIpPortSortField = 'count';
let currentIpPortSortDirection = 'desc';

function sortIpPortStats(field) {
    // 切换排序方向
    if (currentIpPortSortField === field) {
        currentIpPortSortDirection = currentIpPortSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        currentIpPortSortField = field;
        currentIpPortSortDirection = 'asc';
    }
    
    // 重新计算IP端口使用统计
    const ipPortCounts = calculateIpPortStats();
    
    // 收集所有IP地址并为每个IP分配唯一颜色
    const ipColors = {};
    Object.entries(ipPortCounts).forEach(([ipPort, count]) => {
        const [ip] = ipPort.split(':');
        if (!ipColors[ip]) {
            ipColors[ip] = generateUniqueColor(ip);
        }
    });
    
    // 计算总数据包数量
    const totalPackets = currentPackets.length;
    
    // 重新生成表格
    generateIpPortStatsTable(ipPortCounts, ipColors, totalPackets);
}

// 数据包排序函数
function sortPackets(field) {
    // 切换排序方向
    if (currentSortField === field) {
        currentSortDirection = currentSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        currentSortField = field;
        currentSortDirection = 'asc';
    }
    
    // 对数据包进行排序
    currentPackets.sort((a, b) => {
        let aValue, bValue;
        
        // 根据字段获取值
        switch (field) {
            case 'uniqueId':
                aValue = a.uniqueId;
                bValue = b.uniqueId;
                break;
            case 'index':
                aValue = a.uniqueId; // 使用uniqueId作为索引排序的依据
                bValue = b.uniqueId;
                break;
            case 'timestamp':
                aValue = a.timestamp;
                bValue = b.timestamp;
                break;
            case 'srcIp':
                aValue = a.srcIp;
                bValue = b.srcIp;
                break;
            case 'srcPort':
                aValue = a.layers?.transport?.srcPort || 0;
                bValue = b.layers?.transport?.srcPort || 0;
                break;
            case 'dstIp':
                aValue = a.dstIp;
                bValue = b.dstIp;
                break;
            case 'dstPort':
                aValue = a.layers?.transport?.dstPort || 0;
                bValue = b.layers?.transport?.dstPort || 0;
                break;
            case 'protocol':
                aValue = a.protocol;
                bValue = b.protocol;
                break;
            case 'appProtocol':
                aValue = a.layers?.application?.protocol || 'Unknown';
                bValue = b.layers?.application?.protocol || 'Unknown';
                break;
            case 'streamId':
                aValue = a.streamId || 0;
                bValue = b.streamId || 0;
                break;
            case 'packetLen':
                aValue = a.packetLen;
                bValue = b.packetLen;
                break;
            case 'info':
                aValue = a.info;
                bValue = b.info;
                break;
            case 'protocolChain':
                aValue = a.protocolChain || '';
                bValue = b.protocolChain || '';
                break;
            default:
                aValue = '';
                bValue = '';
        }
        
        // 根据值类型进行比较
        let comparison;
        if (typeof aValue === 'number' && typeof bValue === 'number') {
            comparison = aValue - bValue;
        } else {
            comparison = String(aValue).localeCompare(String(bValue));
        }
        
        // 根据排序方向调整结果
        return currentSortDirection === 'asc' ? comparison : -comparison;
    });
    
    // 更新数据包列表
    updatePacketsList(currentPackets);
}

function switchTab(tabName) {
    // 移除所有标签的active类
    const tabBtns = document.querySelectorAll('.tab-btn');
    tabBtns.forEach(btn => btn.classList.remove('active'));
    
    // 隐藏所有标签内容
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(content => content.classList.remove('active'));
    
    // 激活当前标签
    document.querySelector(`[onclick="switchTab('${tabName}')"]`).classList.add('active');
    document.getElementById(tabName).classList.add('active');
    
    // 更新当前列表类型，确保applyAllFilters函数调用正确的过滤函数
    if (tabName === 'flows') {
        currentListType = 'streams';
    } else if (tabName === 'packets') {
        currentListType = 'packets';
    } else if (tabName === 'appRequests') {
        currentListType = 'appRequests';
    }
    
    // 当切换到新的统计标签页时，如果已经加载了文件，生成相应的表格
    if (currentPackets.length > 0) {
        if (tabName === 'ipPortStats') {
            // 计算IP端口使用统计
            const ipPortCounts = calculateIpPortStats();
            
            // 收集所有IP地址并为每个IP分配唯一颜色
            const ipColors = {};
            Object.entries(ipPortCounts).forEach(([ipPort, count]) => {
                const [ip] = ipPort.split(':');
                if (!ipColors[ip]) {
                    ipColors[ip] = generateUniqueColor(ip);
                }
            });
            
            // 计算总数据包数量
            const totalPackets = currentPackets.length;
            
            // 生成IP端口统计表
            generateIpPortStatsTable(ipPortCounts, ipColors, totalPackets);
        } else if (tabName === 'connectionStats') {
            // 计算连接频率统计
            const connectionCounts = calculateConnectionCounts();
            
            // 收集所有IP地址并为每个IP分配唯一颜色
            const ipColors = {};
            Object.keys(connectionCounts).forEach(connection => {
                const [src, dst] = connection.split(' → ');
                const [srcIp] = src.split(':');
                const [dstIp] = dst.split(':');
                
                if (!ipColors[srcIp]) {
                    ipColors[srcIp] = generateUniqueColor(srcIp);
                }
                if (!ipColors[dstIp]) {
                    ipColors[dstIp] = generateUniqueColor(dstIp);
                }
            });
            
            // 按连接次数排序
            const sortedConnections = Object.entries(connectionCounts)
                .sort(([,a], [,b]) => b - a);
            
            // 计算总数据包数量
            const totalPackets = currentPackets.length;
            
            // 生成连接频率统计表
            generateConnectionStatsTable(sortedConnections, ipColors, totalPackets);
        }
    }
}

// 搜索/筛选数据包
function filterPackets() {
    // 检查是否已选择文件
    if (originalPackets.length === 0) {
        // 弹出自定义提示
        showCustomAlert('请选择文件');
        return;
    }
    
    currentSearchKeyword = document.getElementById('searchInput').value;
    // 确保searchText是字符串类型
    const searchText = String(currentSearchKeyword).toLowerCase();
    const filterType = document.getElementById('filterType').value;
    
    // 首先应用搜索过滤
    let filteredPackets = originalPackets;
    
    if (searchText.trim()) {
        // 根据筛选类型过滤数据包
        filteredPackets = originalPackets.filter((packet, index) => {
            const packetInfo = {
                uniqueId: packet.uniqueId.toString(),
                number: (index + 1).toString(),
                time: PcapngParser.formatTime(packet.timestamp).toLowerCase(),
                srcIp: packet.srcIp.toLowerCase(),
                srcPort: (packet.layers?.transport?.srcPort || '-').toString().toLowerCase(),
                dstIp: packet.dstIp.toLowerCase(),
                dstPort: (packet.layers?.transport?.dstPort || '-').toString().toLowerCase(),
                protocolChain: packet.protocolChain.toLowerCase(),
                streamId: (packet.streamId || '-').toString().toLowerCase(),
                packetLen: packet.packetLen.toString(),
                functionDesc: getPacketFunctionDescription(packet).toLowerCase(),
                info: packet.info.toLowerCase()
            };
            
            if (filterType === 'all') {
                // 搜索所有字段
                return Object.values(packetInfo).some(value => value.includes(searchText));
            } else {
                // 搜索特定字段
                return packetInfo[filterType].includes(searchText);
            }
        });
    }
    
    // 然后应用筛选条件
    const tableFilters = filters['packetsTable'] || {};
    if (Object.keys(tableFilters).length > 0) {
        filteredPackets = filteredPackets.filter(packet => {
            return Object.entries(tableFilters).every(([columnIndex, values]) => {
                const colIndex = parseInt(columnIndex);
                let value;
                
                // 根据列索引获取值
                    switch(colIndex) {
                        case 1: value = (packet.uniqueId || '-').toString(); break; // 唯一ID
                        case 4: value = packet.srcIp || '-'; break; // 源IP
                        case 5: value = (packet.layers?.transport?.srcPort || '-').toString(); break; // 源端口
                        case 6: value = packet.dstIp || '-'; break; // 目标IP
                        case 7: value = (packet.layers?.transport?.dstPort || '-').toString(); break; // 目标端口
                        case 8: value = packet.protocolChain || '-'; break; // 协议链
                        case 9: value = (packet.streamId || '-').toString(); break; // 流ID
                        case 10: value = (packet.packetLen || '-').toString(); break; // 长度
                        case 11: value = getPacketFunctionDescription(packet) || '-'; break; // 功能介绍
                        case 12: value = packet.info || '-'; break; // 信息
                        case 13: {
                            // 关键字匹配列
                            // 检查数据包是否匹配关键字
                            let matches = [];
                            
                            // 定义需要检查的数据包属性
                            const packetAttributes = [
                                { name: 'uniqueId', value: packet.uniqueId },
                                { name: 'srcIp', value: packet.srcIp },
                                { name: 'srcPort', value: packet.layers?.transport?.srcPort },
                                { name: 'dstIp', value: packet.dstIp },
                                { name: 'dstPort', value: packet.layers?.transport?.dstPort },
                                { name: 'protocol', value: packet.protocol },
                                { name: 'protocolChain', value: packet.protocolChain },
                                { name: 'info', value: packet.info },
                                { name: 'functionDesc', value: getPacketFunctionDescription(packet) },
                                { name: 'timestamp', value: packet.timestamp },
                                { name: 'packetLen', value: packet.packetLen },
                                { name: 'streamId', value: packet.streamId }
                            ];
                            
                            // 检查应用层数据
                            if (packet.layers?.application) {
                                const appData = packet.layers.application;
                                packetAttributes.push(
                                    { name: 'applicationProtocol', value: appData.protocol },
                                    { name: 'applicationInfo', value: appData.info },
                                    { name: 'httpMethod', value: appData.httpInfo?.method },
                                    { name: 'httpUrl', value: appData.httpInfo?.url },
                                    { name: 'httpHeaders', value: JSON.stringify(appData.httpInfo?.headers) },
                                    { name: 'httpBody', value: appData.httpInfo?.body },
                                    { name: 'httpStatus', value: appData.httpInfo?.status },
                                    { name: 'rawData', value: appData.raw }
                                );
                            }
                            
                            // 检查传输层数据
                            if (packet.layers?.transport) {
                                const transportData = packet.layers.transport;
                                packetAttributes.push(
                                    { name: 'transportType', value: transportData.type },
                                    { name: 'transportInfo', value: transportData.info }
                                );
                            }
                            
                            // 检查网络层数据
                            if (packet.layers?.network) {
                                const networkData = packet.layers.network;
                                packetAttributes.push(
                                    { name: 'networkVersion', value: networkData.version },
                                    { name: 'networkInfo', value: networkData.info }
                                );
                            }
                            
                            // 检查链路层数据
                            if (packet.layers?.link) {
                                const linkData = packet.layers.link;
                                packetAttributes.push(
                                    { name: 'linkType', value: linkData.type },
                                    { name: 'linkInfo', value: linkData.info }
                                );
                            }
                            
                            // 遍历所有属性和关键字，检查是否匹配（仅当开关开启时）
                            if (isKeywordMatchingEnabled()) {
                                packetAttributes.forEach(attr => {
                                    if (attr.value === null || attr.value === undefined || attr.value === '-') {
                                        return;
                                    }
                                    
                                    const attrValue = String(attr.value).toLowerCase();
                                    
                                    keywords.forEach(keyword => {
                                        const keywordLower = keyword.toLowerCase();
                                        if (attrValue.includes(keywordLower)) {
                                            matches.push(keyword);
                                        }
                                    });
                                });
                            }
                            
                            // 去重并排序
                            matches = [...new Set(matches)].sort();
                            value = matches.length > 0 ? matches.join(', ') : '-';
                            break;
                        }
                        default: return true;
                    }
                    
                    // 检查值是否匹配筛选条件
                    // 对于端口号等数值类型，需要处理字符串和数值的比较
                    let match = false;
                    for (const filterValue of values) {
                        if (colIndex === 13) {
                            // 关键字匹配列的特殊处理：检查筛选关键字是否在数据包匹配的关键字列表中
                            // 对于筛选值为"-"的情况，直接比较
                            if (filterValue === '-') {
                                match = value === '-';
                            } else {
                                // 对于其他筛选值，检查是否有交集
                                const valueKeywords = value.split(',').map(k => k.trim());
                                const filterKeywords = filterValue.split(',').map(k => k.trim());
                                // 检查是否有交集
                                match = valueKeywords.some(vk => filterKeywords.includes(vk));
                            }
                        } else {
                            // 其他列：直接比较字符串，因为我们已经将所有值转换为字符串
                            if (value === filterValue) {
                                match = true;
                            }
                        }
                        if (match) {
                            break;
                        }
                    }
                    return match;
            });
        });
    }
    
    currentPackets = filteredPackets;
    currentPage = 1; // 重置到第一页，确保新筛选的结果从第一页开始显示
    updateListWithPagination();
}

// 清除筛选条件
function clearFilter() {
    document.getElementById('searchInput').value = '';
    document.getElementById('filterType').value = 'all';
    currentSearchKeyword = '';
    currentPackets = [...originalPackets];
    updateListWithPagination();
}

// 添加筛选条件行
function addFilter(listType = 'packets') {
    let containerId, rowClass, fieldOptions;
    
    // 根据列表类型设置不同的参数
    switch(listType) {
        case 'flow':
            containerId = 'flowFilterConditions';
            rowClass = 'flow-filter-row';
            fieldOptions = `
                <option value="streamId">流ID</option>
                <option value="srcIp">源IP</option>
                <option value="srcPort">源端口</option>
                <option value="dstIp">目标IP</option>
                <option value="dstPort">目标端口</option>
                <option value="packetCount">数据包数量</option>
                <option value="protocol">协议</option>
                <option value="conversation">流对话</option>
            `;
            break;
        case 'httpUrl':
        case 'appRequest':
            containerId = 'appRequestFilterConditions';
            rowClass = 'appRequest-filter-row';
            fieldOptions = `
                <option value="method">请求方法</option>
                <option value="path">URL路径</option>
                <option value="version">协议版本</option>
                <option value="srcAddr">源IP:端口</option>
                <option value="dstAddr">目标IP:端口</option>
                <option value="responseStatus">响应状态</option>
                <option value="responseSize">响应大小</option>
                <option value="host">Host</option>
                <option value="userAgent">User-Agent</option>
                <option value="accept">Accept</option>
                <option value="acceptLanguage">Accept-Language</option>
                <option value="cookie">Cookie</option>
                <option value="contentType">Content-Type</option>
                <option value="responseContentType">响应内容类型</option>
                <option value="server">服务器</option>
                <option value="responseTime">响应时间</option>
                <option value="requestDetails">请求详情</option>
                <option value="responseDetails">响应详情</option>
                <option value="requestBody">请求体内容</option>
                <option value="responseBody">响应体内容</option>
            `;
            break;
        case 'packets':
        default:
            containerId = 'filterConditions';
            rowClass = 'filter-row';
            fieldOptions = `
                <option value="uniqueId">唯一ID</option>
                <option value="srcIp">源IP</option>
                <option value="srcPort">源端口</option>
                <option value="dstIp">目标IP</option>
                <option value="dstPort">目标端口</option>
                <option value="protocolChain">协议</option>
                <option value="streamId">流ID</option>
                <option value="packetLen">长度</option>
                <option value="functionDesc">功能介绍</option>
                <option value="info">信息</option>
            `;
            break;
    }
    
    const filterConditions = document.getElementById(containerId);
    const newFilterRow = document.createElement('div');
    newFilterRow.className = rowClass;
    newFilterRow.style.display = 'flex';
    newFilterRow.style.gap = '10px';
    newFilterRow.style.alignItems = 'center';
    
    newFilterRow.innerHTML = `
        <select class="filter-field" style="padding: 6px; border: 1px solid #ddd; border-radius: 4px;">
            ${fieldOptions}
        </select>
        <select class="filter-operator" style="padding: 6px; border: 1px solid #ddd; border-radius: 4px;">
            <option value="contains">包含</option>
            <option value="equals">等于</option>
            <option value="startsWith">开始于</option>
            <option value="endsWith">结束于</option>
            <option value="notContains">不包含</option>
            <option value="notEquals">不等于</option>
            <option value="greaterThan">大于</option>
            <option value="lessThan">小于</option>
        </select>
        <input type="text" class="filter-value" placeholder="筛选值" style="flex: 1; padding: 6px; border: 1px solid #ddd; border-radius: 4px; text-align: left; direction: ltr; unicode-bidi: bidi-override;" dir="ltr">
        <select class="filter-logic" style="padding: 6px; border: 1px solid #ddd; border-radius: 4px;">
            <option value="AND">AND</option>
            <option value="OR">OR</option>
        </select>
        <button class="remove-filter" onclick="removeFilter(this, '${listType}')" style="padding: 6px 12px; background-color: #e74c3c; color: white; border: none; border-radius: 4px; cursor: pointer;">删除</button>
    `;
    
    filterConditions.appendChild(newFilterRow);
}

// 删除筛选条件行
function removeFilter(button, listType = 'packets') {
    const filterRow = button.parentElement;
    let filterConditions;
    
    // 根据列表类型获取不同的容器
    switch(listType) {
        case 'flow':
            filterConditions = document.getElementById('flowFilterConditions');
            break;
        case 'httpUrl':
        case 'appRequest':
            filterConditions = document.getElementById('appRequestFilterConditions');
            break;
        case 'packets':
        default:
            filterConditions = document.getElementById('filterConditions');
            break;
    }
    
    // 确保至少保留一行筛选条件
    if (filterConditions.children.length > 1) {
        filterConditions.removeChild(filterRow);
    }
}

// 应用高级筛选
function applyAdvancedFilter(listType = 'packets') {
    let filterRows, filters = [];
    
    // 根据列表类型获取筛选条件行
    switch(listType) {
        case 'flow':
            filterRows = document.querySelectorAll('.flow-filter-row');
            break;
        case 'httpUrl':
        case 'appRequest':
            filterRows = document.querySelectorAll('.httpUrl-filter-row, .appRequest-filter-row');
            break;
        case 'packets':
        default:
            filterRows = document.querySelectorAll('.filter-row');
            break;
    }
    
    // 收集所有筛选条件
    filterRows.forEach(row => {
        const field = row.querySelector('.filter-field').value;
        const operator = row.querySelector('.filter-operator').value;
        const value = row.querySelector('.filter-value').value.toLowerCase();
        const logic = row.querySelector('.filter-logic').value;
        
        if (value.trim()) {
            filters.push({ field, operator, value, logic });
        }
    });
    
    if (filters.length === 0) {
        // 如果没有筛选条件，显示所有数据
        if (listType === 'flow') {
            currentStreams = originalStreams;
            updateStreamsList(currentStreams);
        } else if (listType === 'httpUrl' || listType === 'appRequest') {
            updateAppRequestsList();
        } else {
            currentPackets = [...originalPackets];
            currentPage = 1; // 重置到第一页，确保新筛选的结果从第一页开始显示
            updateListWithPagination();
        }
        return;
    }
    
    // 根据不同列表类型应用筛选逻辑
    if (listType === 'flow') {
        // 应用流列表筛选
        let filteredStreams = {};
        
        for (const [streamId, stream] of Object.entries(originalStreams)) {
            let result = true;
            
            for (let i = 0; i < filters.length; i++) {
                const filter = filters[i];
                let streamValue;
                
                // 初始化匹配结果
                let match = false;
                
                // 处理流对话字段的特殊情况
                if (filter.field === 'conversation') {
                    // 检查流对话是否匹配筛选条件
                    const conversationContent = stream.conversation.map(msg => {
                        const msgContent = msg.raw || msg.info;
                        return msgContent.toLowerCase();
                    }).join(' ');
                    
                    switch (filter.operator) {
                        case 'contains':
                            match = conversationContent.includes(filter.value);
                            break;
                        case 'notContains':
                            match = !conversationContent.includes(filter.value);
                            break;
                        default:
                            // 流对话只支持包含和不包含操作符
                            match = false;
                    }
                } else {
                    // 获取流对应字段的值
                    let streamValue = '';
                    switch (filter.field) {
                        case 'streamId':
                            streamValue = streamId.toLowerCase();
                            break;
                        case 'srcIp':
                            streamValue = stream.srcIp.toLowerCase();
                            break;
                        case 'srcPort':
                            streamValue = stream.srcPort.toString().toLowerCase();
                            break;
                        case 'dstIp':
                            streamValue = stream.dstIp.toLowerCase();
                            break;
                        case 'dstPort':
                            streamValue = stream.dstPort.toString().toLowerCase();
                            break;
                        case 'packetCount':
                            streamValue = stream.packets.length.toString().toLowerCase();
                            break;
                        case 'protocol':
                            // 确定流的主要协议
                            let protocol = 'Unknown';
                            if (stream.packets.length > 0) {
                                const streamPackets = getStreamPackets(stream);
                                const appProtocols = streamPackets
                                    .filter(packet => packet.layers?.application)
                                    .map(packet => packet.layers.application.protocol)
                                    .filter(Boolean)
                                    .filter(protocol => protocol !== 'Unknown'); // 排除Unknown协议
                                
                                if (appProtocols.length > 0) {
                                    const protocolCounts = appProtocols.reduce((acc, curr) => {
                                        acc[curr] = (acc[curr] || 0) + 1;
                                        return acc;
                                    }, {});
                                    
                                    protocol = Object.entries(protocolCounts)
                                        .sort(([,a], [,b]) => b - a)
                                        [0][0];
                                } else {
                                    protocol = streamPackets[0].protocol;
                                }
                            }
                            streamValue = protocol.toLowerCase();
                            break;
                        default:
                            streamValue = '';
                    }
                    
                    // 根据操作符判断条件是否匹配
                    const isNumericField = ['streamId', 'packetCount', 'srcPort', 'dstPort'].includes(filter.field);
                    const numericStreamValue = isNumericField ? parseFloat(streamValue) : null;
                    const numericFilterValue = isNumericField ? parseFloat(filter.value) : null;
                    
                    switch (filter.operator) {
                        case 'contains':
                            match = streamValue.includes(filter.value);
                            break;
                        case 'equals':
                            if (isNumericField && !isNaN(numericStreamValue) && !isNaN(numericFilterValue)) {
                                match = numericStreamValue === numericFilterValue;
                            } else {
                                match = streamValue === filter.value;
                            }
                            break;
                        case 'startsWith':
                            match = streamValue.startsWith(filter.value);
                            break;
                        case 'endsWith':
                            match = streamValue.endsWith(filter.value);
                            break;
                        case 'notContains':
                            match = !streamValue.includes(filter.value);
                            break;
                        case 'notEquals':
                            if (isNumericField && !isNaN(numericStreamValue) && !isNaN(numericFilterValue)) {
                                match = numericStreamValue !== numericFilterValue;
                            } else {
                                match = streamValue !== filter.value;
                            }
                            break;
                        case 'greaterThan':
                            match = !isNaN(numericStreamValue) && !isNaN(numericFilterValue) && numericStreamValue > numericFilterValue;
                            break;
                        case 'lessThan':
                            match = !isNaN(numericStreamValue) && !isNaN(numericFilterValue) && numericStreamValue < numericFilterValue;
                            break;
                        default:
                            match = false;
                    }
                }
                
                // 根据逻辑操作符更新结果
                if (i === 0) {
                    result = match;
                } else {
                    if (filter.logic === 'AND') {
                        result = result && match;
                    } else {
                        result = result || match;
                    }
                }
            }
            
            if (result) {
                filteredStreams[streamId] = stream;
            }
        }
        
        currentStreams = filteredStreams;
        updateStreamsList(currentStreams);
    } else if (listType === 'httpUrl' || listType === 'appRequest') {
        // 应用HTTP请求URL列表筛选
        // 获取所有应用层请求数据包，包括HTTP和非HTTP协议
        const httpPackets = originalPackets.filter(packet => {
            return packet.layers?.application?.protocol && 
                   packet.layers.application.protocol !== 'Unknown';
        });
        
        const filteredHttpPackets = httpPackets.filter(packet => {
            let result = true;
            const httpInfo = packet.layers.application.httpInfo;
            const srcAddr = `${packet.srcIp}:${packet.layers?.transport?.srcPort || '-'}`;
            const dstAddr = `${packet.dstIp}:${packet.layers?.transport?.dstPort || '-'}`;
            
            for (let i = 0; i < filters.length; i++) {
                const filter = filters[i];
                let packetValue;
                
                // 获取HTTP请求对应字段的值
                switch (filter.field) {
                    case 'method':
                        // 对于HTTP协议，使用httpInfo.method；对于非HTTP协议，使用协议名称
                        packetValue = httpInfo ? (httpInfo.method || '').toLowerCase() : packet.layers.application.protocol.toLowerCase();
                        break;
                    case 'path':
                        // 对于HTTP协议，使用httpInfo.path；对于非HTTP协议，使用应用层rawInfo或info字段
                        packetValue = httpInfo ? (httpInfo.path || '').toLowerCase() : (packet.layers.application.rawInfo || packet.layers.application.info || '').toLowerCase();
                        break;
                    case 'version':
                        packetValue = (httpInfo.httpVersion || '').toLowerCase();
                        break;
                    case 'srcAddr':
                        packetValue = srcAddr.toLowerCase();
                        break;
                    case 'dstAddr':
                        packetValue = dstAddr.toLowerCase();
                        break;
                    case 'responseStatus':
                        const responsePacket = getHttpResponseForRequest(packet);
                        if (responsePacket?.layers?.application?.httpInfo?.statusCode) {
                            const statusCode = responsePacket.layers.application.httpInfo.statusCode;
                            const statusText = responsePacket.layers.application.httpInfo.statusText || '';
                            packetValue = `${statusCode} ${statusText}`.toLowerCase();
                        } else {
                            packetValue = '-';
                        }
                        break;
                    case 'responseSize':
                        const response = getHttpResponseForRequest(packet);
                        packetValue = response ? response.packetLen.toString().toLowerCase() : '-';
                        break;
                    case 'host':
                        packetValue = (httpInfo.headers?.Host || '').toLowerCase();
                        break;
                    case 'userAgent':
                        packetValue = (httpInfo.headers?.['User-Agent'] || '').toLowerCase();
                        break;
                    case 'accept':
                        packetValue = (httpInfo.headers?.Accept || '').toLowerCase();
                        break;
                    case 'acceptLanguage':
                        packetValue = (httpInfo.headers?.['Accept-Language'] || '').toLowerCase();
                        break;
                    case 'cookie':
                        packetValue = (httpInfo.headers?.Cookie || '').toLowerCase();
                        break;
                    case 'contentType':
                        packetValue = (httpInfo.headers?.['Content-Type'] || '').toLowerCase();
                        break;
                    case 'responseContentType':
                        const resp = getHttpResponseForRequest(packet);
                        packetValue = (resp?.layers?.application?.httpInfo?.headers?.['Content-Type'] || '').toLowerCase();
                        break;
                    case 'server':
                        const responsePack = getHttpResponseForRequest(packet);
                        packetValue = (responsePack?.layers?.application?.httpInfo?.headers?.Server || '').toLowerCase();
                        break;
                    case 'responseTime':
                        const responsePkt = getHttpResponseForRequest(packet);
                        packetValue = responsePkt ? (responsePkt.timestamp - packet.timestamp).toFixed(3).toLowerCase() : '-';
                        break;
                    case 'requestDetails':
                        // 提取请求详情
                        let requestDetails;
                        if (httpInfo) {
                            requestDetails = httpInfo.raw || httpInfo.body || '';
                        } else {
                            requestDetails = packet.layers.application.raw || packet.layers.application.rawInfo || packet.layers.application.info || '';
                        }
                        packetValue = requestDetails.toLowerCase();
                        break;
                    case 'responseDetails':
                        // 提取响应详情
                        let responseDetails;
                        const responsePacketForDetails = getHttpResponseForRequest(packet);
                        if (responsePacketForDetails) {
                            const responseAppInfo = responsePacketForDetails.layers.application;
                            if (responseAppInfo.httpInfo) {
                                responseDetails = responseAppInfo.httpInfo.raw || responseAppInfo.httpInfo.body || '';
                            } else {
                                responseDetails = responseAppInfo.raw || responseAppInfo.info || '';
                            }
                        } else {
                            responseDetails = '';
                        }
                        packetValue = responseDetails.toLowerCase();
                        break;
                    case 'requestBody':
                        // 提取请求体内容
                        let requestBody;
                        if (httpInfo) {
                            requestBody = httpInfo.body || '';
                        } else {
                            requestBody = '';
                        }
                        packetValue = requestBody.toLowerCase();
                        break;
                    case 'responseBody':
                        // 提取响应体内容
                        let responseBody;
                        const responsePacketForBody = getHttpResponseForRequest(packet);
                        if (responsePacketForBody) {
                            const responseAppInfo = responsePacketForBody.layers.application;
                            if (responseAppInfo.httpInfo) {
                                responseBody = responseAppInfo.httpInfo.body || '';
                            } else {
                                responseBody = '';
                            }
                        } else {
                            responseBody = '';
                        }
                        packetValue = responseBody.toLowerCase();
                        break;
                    default:
                        packetValue = '';
                }
                
                // 根据操作符判断条件是否匹配
                let match = false;
                const isNumericField = ['responseSize', 'responseTime'].includes(filter.field);
                const numericPacketValue = isNumericField ? parseFloat(packetValue) : null;
                const numericFilterValue = isNumericField ? parseFloat(filter.value) : null;
                
                switch (filter.operator) {
                    case 'contains':
                        match = packetValue.includes(filter.value);
                        break;
                    case 'equals':
                        if (isNumericField && !isNaN(numericPacketValue) && !isNaN(numericFilterValue)) {
                            match = numericPacketValue === numericFilterValue;
                        } else {
                            match = packetValue === filter.value;
                        }
                        break;
                    case 'startsWith':
                        match = packetValue.startsWith(filter.value);
                        break;
                    case 'endsWith':
                        match = packetValue.endsWith(filter.value);
                        break;
                    case 'notContains':
                        match = !packetValue.includes(filter.value);
                        break;
                    case 'notEquals':
                        if (isNumericField && !isNaN(numericPacketValue) && !isNaN(numericFilterValue)) {
                            match = numericPacketValue !== numericFilterValue;
                        } else {
                            match = packetValue !== filter.value;
                        }
                        break;
                    case 'greaterThan':
                        match = !isNaN(numericPacketValue) && !isNaN(numericFilterValue) && numericPacketValue > numericFilterValue;
                        break;
                    case 'lessThan':
                        match = !isNaN(numericPacketValue) && !isNaN(numericFilterValue) && numericPacketValue < numericFilterValue;
                        break;
                    default:
                        match = false;
                }
                
                // 根据逻辑操作符更新结果
                if (i === 0) {
                    result = match;
                } else {
                    if (filter.logic === 'AND') {
                        result = result && match;
                    } else {
                        result = result || match;
                    }
                }
            }
            
            return result;
        });
        
        // 更新HTTP请求URL列表，传入过滤后的数据包
        updateAppRequestsList(filteredHttpPackets);
    } else {
        // 应用数据包列表筛选
        currentPackets = originalPackets.filter(packet => {
            let result = true;
            let lastResult = true;
            
            for (let i = 0; i < filters.length; i++) {
                const filter = filters[i];
                let packetValue;
                
                // 获取数据包对应字段的值
                switch (filter.field) {
                    case 'uniqueId':
                        packetValue = packet.uniqueId.toString().toLowerCase();
                        break;
                    case 'srcIp':
                        packetValue = packet.srcIp.toLowerCase();
                        break;
                    case 'srcPort':
                        packetValue = (packet.layers?.transport?.srcPort || '-').toString().toLowerCase();
                        break;
                    case 'dstIp':
                        packetValue = packet.dstIp.toLowerCase();
                        break;
                    case 'dstPort':
                        packetValue = (packet.layers?.transport?.dstPort || '-').toString().toLowerCase();
                        break;
                    case 'protocolChain':
                        packetValue = packet.protocolChain.toLowerCase();
                        break;
                    case 'streamId':
                        packetValue = (packet.streamId || '-').toString().toLowerCase();
                        break;
                    case 'packetLen':
                        packetValue = packet.packetLen.toString().toLowerCase();
                        break;
                    case 'info':
                        packetValue = packet.info.toLowerCase();
                        break;
                    case 'functionDesc':
                        packetValue = getPacketFunctionDescription(packet).toLowerCase();
                        break;
                    default:
                        packetValue = '';
                }
                
                // 根据操作符判断条件是否匹配
                let match = false;
                // 对于数值类型字段，转换为数字进行比较
                const isNumericField = ['uniqueId', 'srcPort', 'dstPort', 'streamId', 'packetLen'].includes(filter.field);
                const numericPacketValue = isNumericField ? parseFloat(packetValue) : null;
                const numericFilterValue = isNumericField ? parseFloat(filter.value) : null;
                
                switch (filter.operator) {
                    case 'contains':
                        match = packetValue.includes(filter.value);
                        break;
                    case 'equals':
                        if (isNumericField && !isNaN(numericPacketValue) && !isNaN(numericFilterValue)) {
                            match = numericPacketValue === numericFilterValue;
                        } else {
                            match = packetValue === filter.value;
                        }
                        break;
                    case 'startsWith':
                        match = packetValue.startsWith(filter.value);
                        break;
                    case 'endsWith':
                        match = packetValue.endsWith(filter.value);
                        break;
                    case 'notContains':
                        match = !packetValue.includes(filter.value);
                        break;
                    case 'notEquals':
                        if (isNumericField && !isNaN(numericPacketValue) && !isNaN(numericFilterValue)) {
                            match = numericPacketValue !== numericFilterValue;
                        } else {
                            match = packetValue !== filter.value;
                        }
                        break;
                    case 'greaterThan':
                        match = !isNaN(numericPacketValue) && !isNaN(numericFilterValue) && numericPacketValue > numericFilterValue;
                        break;
                    case 'lessThan':
                        match = !isNaN(numericPacketValue) && !isNaN(numericFilterValue) && numericPacketValue < numericFilterValue;
                        break;
                    default:
                        match = false;
                }
                
                // 根据逻辑操作符更新结果
                if (i === 0) {
                    result = match;
                } else {
                    if (filter.logic === 'AND') {
                        result = result && match;
                    } else {
                        result = result || match;
                    }
                }
            }
            
            return result;
        });
        
        // 更新数据包列表
        updatePacketsList(currentPackets);
    }
}

// 清除高级筛选
function clearAdvancedFilter(listType = 'packets') {
    let filterConditions, firstRow;
    
    // 根据列表类型获取不同的容器
    switch(listType) {
        case 'flow':
            filterConditions = document.getElementById('flowFilterConditions');
            break;
        case 'httpUrl':
        case 'appRequest':
            filterConditions = document.getElementById('appRequestFilterConditions');
            break;
        case 'packets':
        default:
            filterConditions = document.getElementById('filterConditions');
            break;
    }
    
    firstRow = filterConditions.firstElementChild;
    
    // 清空所有筛选条件行，只保留第一行
    filterConditions.innerHTML = '';
    filterConditions.appendChild(firstRow);
    
    // 清空第一行的值
    firstRow.querySelector('.filter-value').value = '';
    
    // 根据不同列表类型显示所有数据
    if (listType === 'flow') {
        currentStreams = originalStreams;
        updateStreamsList(currentStreams);
    } else if (listType === 'httpUrl') {
        updateAppRequestsList();
    } else {
        currentPackets = [...originalPackets];
        updatePacketsList(currentPackets);
    }
}

// 导出数据包列表为XLSX
function exportPacketsToXLSX() {
    if (currentPackets.length === 0) {
        alert('没有数据包可导出');
        return;
    }
    
    // 定义XLSX列标题，包含功能介绍字段
    const headers = [
        '唯一ID', '序号', '时间', '源IP', '源端口', '目标IP', '目标端口',
        '协议', '流ID', '长度', '功能介绍', '信息'
    ];
    
    // 定义XLSX数据行
    const rows = currentPackets.map((packet, index) => {
        // 获取流ID
        const streamId = packet.streamId || '-';
        // 获取唯一ID
        const uniqueId = packet.uniqueId || '-';
        // 获取源端口和目标端口
        const srcPort = packet.layers?.transport?.srcPort || '-';
        const dstPort = packet.layers?.transport?.dstPort || '-';
        // 获取数据包功能介绍
        const functionDesc = getPacketFunctionDescription(packet);
        // 获取协议链
        const protocol = packet.protocolChain || packet.protocol || 'Unknown';
        
        return {
            '唯一ID': uniqueId,
            '序号': index + 1,
            '时间': PcapngParser.formatTime(packet.timestamp),
            '源IP': packet.srcIp,
            '源端口': srcPort,
            '目标IP': packet.dstIp,
            '目标端口': dstPort,
            '协议': protocol,
            '流ID': streamId,
            '长度': packet.packetLen,
            '功能介绍': functionDesc,
            '信息': packet.info
        };
    });
    
    // 创建工作簿
    const wb = XLSX.utils.book_new();
    
    // 创建工作表
    const ws = XLSX.utils.json_to_sheet(rows, { header: headers });
    
    // 设置列宽
    const colWidths = [
        { wch: 20 }, // 唯一ID
        { wch: 8 }, // 序号
        { wch: 20 }, // 时间
        { wch: 15 }, // 源IP
        { wch: 10 }, // 源端口
        { wch: 15 }, // 目标IP
        { wch: 10 }, // 目标端口
        { wch: 15 }, // 协议
        { wch: 10 }, // 流ID
        { wch: 10 }, // 长度
        { wch: 25 }, // 功能介绍
        { wch: 30 } // 信息
    ];
    ws['!cols'] = colWidths;
    
    // 添加工作表到工作簿
    XLSX.utils.book_append_sheet(wb, ws, '数据包列表');
    
    // 导出为XLSX文件
    XLSX.writeFile(wb, `packets_${new Date().getTime()}.xlsx`);
}

// 流搜索筛选函数
function filterFlows() {
    // 检查是否已选择文件
    if (Object.keys(originalStreams).length === 0) {
        // 弹出自定义提示
        showCustomAlert('请选择文件');
        return;
    }
    
    currentFlowSearchKeyword = document.getElementById('flowSearchInput').value;
    // 确保searchText是字符串类型
    const searchText = String(currentFlowSearchKeyword).toLowerCase();
    const filterType = document.getElementById('flowFilterType').value;
    const tableFilters = filters['flowsTable'] || {};
    
    // 从原始流列表开始，同时应用搜索过滤和表头筛选
    let filteredStreams = {};
    
    // 遍历所有原始流
    for (const [streamId, stream] of Object.entries(originalStreams)) {
        // 确定流的主要协议，与updateStreamsList中的逻辑保持一致
        let protocol = 'Unknown';
        if (stream.packets.length > 0) {
            const streamPackets = getStreamPackets(stream);
            const appProtocols = streamPackets
                .filter(packet => packet.layers?.application)
                .map(packet => packet.layers.application.protocol)
                .filter(Boolean)
                .filter(protocol => protocol !== 'Unknown'); // 排除Unknown协议
            
            // 找出出现次数最多的协议
            if (appProtocols.length > 0) {
                const protocolCounts = appProtocols.reduce((acc, curr) => {
                    acc[curr] = (acc[curr] || 0) + 1;
                    return acc;
                }, {});
                
                protocol = Object.entries(protocolCounts)
                    .sort(([,a], [,b]) => b - a)
                    [0][0];
            } else {
                protocol = streamPackets[0].protocol;
            }
        }
        
        // 计算流的总长度
        const streamPackets = getStreamPackets(stream);
        const totalLength = streamPackets.reduce((sum, packet) => sum + (packet.packetLen || 0), 0);
        
        const streamInfo = {
            streamId: streamId,
            src: `${stream.srcIp}:${stream.srcPort}`,
            dst: `${stream.dstIp}:${stream.dstPort}`,
            srcIp: stream.srcIp,
            srcPort: stream.srcPort.toString(),
            dstIp: stream.dstIp,
            dstPort: stream.dstPort.toString(),
            packetCount: stream.packets.length.toString(),
            totalLength: totalLength,
            protocol: protocol
        };
        
        let matchesSearch = !searchText.trim();
        let matchesAllFilters = true;
        
        // 检查搜索过滤
        if (searchText.trim()) {
            if (filterType === 'all') {
                // 搜索所有字段，包括流对话
                matchesSearch = Object.values(streamInfo).some(value => {
                    // 确保value是字符串类型
                    return String(value).toLowerCase().includes(searchText);
                });
                
                // 如果不匹配普通字段，检查流对话
                if (!matchesSearch && stream.conversation) {
                    matchesSearch = stream.conversation.some(msg => {
                        const msgContent = msg.raw || msg.info || '';
                        // 确保msgContent是字符串类型
                        return String(msgContent).toLowerCase().includes(searchText);
                    });
                }
            } else if (filterType === 'conversation') {
                // 搜索流对话
                matchesSearch = stream.conversation.some(msg => {
                    const msgContent = msg.raw || msg.info || '';
                    // 确保msgContent是字符串类型
                    return String(msgContent).toLowerCase().includes(searchText);
                });
            } else {
                // 搜索特定字段
                const fieldValue = streamInfo[filterType];
                // 确保fieldValue是字符串类型
                matchesSearch = String(fieldValue).toLowerCase().includes(searchText);
            }
        }
        
        // 检查表头筛选
        if (Object.keys(tableFilters).length > 0) {
            for (const [columnIndex, values] of Object.entries(tableFilters)) {
                const colIndex = parseInt(columnIndex);
                let value;
                
                // 根据列索引获取值
                switch(colIndex) {
                    case 0: value = streamInfo.streamId; break; // 流ID
                    case 1: value = streamInfo.src; break; // 源IP:端口
                    case 2: value = streamInfo.dst; break; // 目标IP:端口
                    case 3: value = streamInfo.packetCount; break; // 数据包数量
                    case 4: value = streamInfo.totalLength.toString(); break; // 长度
                    case 5: value = streamInfo.protocol; break; // 协议
                    default: continue;
                }
                
                if (!values.includes(value)) {
                    matchesAllFilters = false;
                    break;
                }
            }
        }
        
        // 只有同时满足搜索过滤和表头筛选条件的流才会被保留
        if (matchesSearch && matchesAllFilters) {
            filteredStreams[streamId] = stream;
        }
    }
    
    currentStreams = filteredStreams;
    updateStreamsList(currentStreams);
}

// 流列表排序函数
let currentFlowSortField = null;
let currentFlowSortDirection = 'asc'; // 'asc' 或 'desc'
let sortedStreamArray = null; // 保存排序后的流数组，用于保持排序状态

function sortFlows(field) {
    // 切换排序方向
    if (currentFlowSortField === field) {
        currentFlowSortDirection = currentFlowSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        currentFlowSortField = field;
        currentFlowSortDirection = 'asc';
    }
    
    // 重置到第一页，确保用户看到完整的排序结果
    currentPage = 1;
    
    // 获取当前流列表的副本，避免修改原始currentStreams对象
    const streamArray = Object.values(currentStreams);
    
    // 对流列表进行排序
    streamArray.sort((a, b) => {
        let aValue, bValue;
        
        // 根据字段获取值
        switch (field) {
            case 'streamId':
                aValue = parseInt(a.id) || 0;
                bValue = parseInt(b.id) || 0;
                break;
            case 'src':
                aValue = `${a.srcIp}:${a.srcPort}`;
                bValue = `${b.srcIp}:${b.srcPort}`;
                break;
            case 'dst':
                aValue = `${a.dstIp}:${a.dstPort}`;
                bValue = `${b.dstIp}:${b.dstPort}`;
                break;
            case 'packetCount':
                aValue = a.packets.length;
                bValue = b.packets.length;
                break;
            case 'totalLength':
                // 计算流的总长度
                aValue = a.packets.reduce((sum, packet) => sum + (packet.packetLen || 0), 0);
                bValue = b.packets.reduce((sum, packet) => sum + (packet.packetLen || 0), 0);
                break;
            case 'protocol': {
                // 确定流的主要协议，与updateStreamsList中的逻辑保持一致
                let aProtocol = 'Unknown';
                if (a.packets.length > 0) {
                    const aAppProtocols = a.packets
                        .filter(packet => packet.layers?.application)
                        .map(packet => packet.layers.application.protocol)
                        .filter(Boolean);
                    
                    // 找出出现次数最多的协议
                    if (aAppProtocols.length > 0) {
                        const aProtocolCounts = aAppProtocols.reduce((acc, curr) => {
                            acc[curr] = (acc[curr] || 0) + 1;
                            return acc;
                        }, {});
                        
                        aProtocol = Object.entries(aProtocolCounts)
                            .sort(([,aCount], [,bCount]) => bCount - aCount)
                            [0][0];
                    } else {
                        aProtocol = a.packets[0].protocol;
                    }
                }
                
                let bProtocol = 'Unknown';
                if (b.packets.length > 0) {
                    const bAppProtocols = b.packets
                        .filter(packet => packet.layers?.application)
                        .map(packet => packet.layers.application.protocol)
                        .filter(Boolean);
                    
                    // 找出出现次数最多的协议
                    if (bAppProtocols.length > 0) {
                        const bProtocolCounts = bAppProtocols.reduce((acc, curr) => {
                            acc[curr] = (acc[curr] || 0) + 1;
                            return acc;
                        }, {});
                        
                        bProtocol = Object.entries(bProtocolCounts)
                            .sort(([,aCount], [,bCount]) => bCount - aCount)
                            [0][0];
                    } else {
                        bProtocol = b.packets[0].protocol;
                    }
                }
                
                aValue = aProtocol;
                bValue = bProtocol;
                break;
            }
            default:
                aValue = '';
                bValue = '';
        }
        
        // 根据值类型进行比较
        let comparison;
        if (typeof aValue === 'number' && typeof bValue === 'number') {
            comparison = aValue - bValue;
        } else {
            comparison = String(aValue).localeCompare(String(bValue));
        }
        
        // 根据排序方向调整结果
        return currentFlowSortDirection === 'asc' ? comparison : -comparison;
    });
    
    // 保存排序后的流数组，用于保持排序状态
    sortedStreamArray = [...streamArray];
    
    // 同时更新currentStreams对象，确保后续操作使用排序后的流列表
    // 注意：这里仍然需要更新currentStreams对象，因为其他函数可能会直接访问它
    const sortedStreams = {};
    streamArray.forEach(stream => {
        sortedStreams[stream.id] = stream;
    });
    currentStreams = sortedStreams;
    
    // 直接传递排序后的数组给updateStreamsList函数，确保排序顺序正确
    updateStreamsList(sortedStreamArray);
}

// 清除流搜索筛选
function clearFlowFilter() {
    document.getElementById('flowSearchInput').value = '';
    currentFlowSearchKeyword = '';
    currentStreams = originalStreams;
    updateStreamsList(currentStreams);
}

// 显示安全检测详情
function showSecurityDetails(httpIndex) {
    // 过滤出所有应用层请求数据包（与应用层请求列表使用相同的过滤条件）
    const appPackets = originalPackets.filter(packet => {
        return packet.layers?.application && 
               packet.layers.application.protocol &&
               packet.layers.application.protocol !== 'Unknown' &&
               // 只保留请求：HTTP请求有method字段，响应有statusCode字段
               (packet.layers.application.httpInfo ? 
                packet.layers.application.httpInfo.method !== undefined && 
                packet.layers.application.httpInfo.statusCode === undefined : 
                true);
    });
    
    const packet = appPackets[httpIndex];
    if (!packet || !packet.securityResult) {
        alert('未找到安全检测结果');
        return;
    }
    
    const securityResult = packet.securityResult;
    const httpInfo = packet.layers.application.httpInfo;
    const appProtocol = packet.layers.application.protocol;
    
    // 生成安全详情HTML
    let html = `
        <div style="max-width: 800px; margin: 0 auto; padding: 20px; background-color: white; border-radius: 8px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);">
            <h3 style="margin-bottom: 20px; color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 10px;">安全检测详情</h3>
            
            <!-- 请求信息 -->
            <div style="margin-bottom: 20px; border: 1px solid #ddd; border-radius: 8px; padding: 15px; background-color: #f9f9f9;">
                <h4 style="margin-bottom: 15px; color: #34495e;">请求信息</h4>
                <table style="width: 100%; border-collapse: collapse;">`;
    
    // 根据协议类型显示不同的请求信息
    if (httpInfo) {
        // HTTP协议
        html += `
                    <tr>
                        <td style="padding: 8px; width: 150px; font-weight: bold; border: 1px solid #eee; background-color: #f5f5f5; font-family: Arial, sans-serif;">请求方法</td>
                        <td style="padding: 8px; border: 1px solid #eee; font-family: Arial, sans-serif;">${httpInfo.method || '-'}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; font-weight: bold; border: 1px solid #eee; background-color: #f5f5f5; font-family: Arial, sans-serif;">URL路径</td>
                        <td style="padding: 8px; border: 1px solid #eee; font-family: monospace; word-break: break-all;">${urlDecode(httpInfo.path || '') || '-'}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; font-weight: bold; border: 1px solid #eee; background-color: #f5f5f5; font-family: Arial, sans-serif;">HTTP版本</td>
                        <td style="padding: 8px; border: 1px solid #eee; font-family: Arial, sans-serif;">${httpInfo.version || 'Unknown'}</td>
                    </tr>`;
    } else {
        // 非HTTP协议
        html += `
                    <tr>
                        <td style="padding: 8px; width: 150px; font-weight: bold; border: 1px solid #eee; background-color: #f5f5f5; font-family: Arial, sans-serif;">协议类型</td>
                        <td style="padding: 8px; border: 1px solid #eee; font-family: Arial, sans-serif;">${appProtocol || '-'}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; font-weight: bold; border: 1px solid #eee; background-color: #f5f5f5; font-family: Arial, sans-serif;">协议信息</td>
                        <td style="padding: 8px; border: 1px solid #eee; font-family: monospace; word-break: break-all;">${packet.layers.application.rawInfo || packet.layers.application.info || '-'}</td>
                    </tr>`;
    }
    
    // 继续添加通用的请求信息
    html += `
                    <tr>
                        <td style="padding: 8px; font-weight: bold; border: 1px solid #eee; background-color: #f5f5f5; font-family: Arial, sans-serif;">源IP:端口</td>
                        <td style="padding: 8px; border: 1px solid #eee; font-family: Arial, sans-serif;">${packet.srcIp}:${packet.layers?.transport?.srcPort || '-'}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; font-weight: bold; border: 1px solid #eee; background-color: #f5f5f5; font-family: Arial, sans-serif;">目标IP:端口</td>
                        <td style="padding: 8px; border: 1px solid #eee; font-family: Arial, sans-serif;">${packet.dstIp}:${packet.layers?.transport?.dstPort || '-'}</td>
                    </tr>
                </table>
            </div>
            
            <!-- 安全检测结果 -->
            <div style="margin-bottom: 20px; border: 1px solid #ddd; border-radius: 8px; padding: 15px; background-color: #f9f9f9;">
                <h4 style="margin-bottom: 15px; color: #34495e;">安全检测结果</h4>
                <div style="margin-bottom: 20px; padding: 12px; border-radius: 4px; ${securityResult.isSecure ? 'background-color: #e8f5e8; color: #2e7d32;' : 'background-color: #ffebee; color: #c62828;'}">
                    <strong style="font-size: 16px;">整体状态：${securityResult.isSecure ? '安全' : '危险'}</strong>
                </div>
                
                ${!securityResult.isSecure ? `
                    <div style="margin-bottom: 20px;">
                        <h5 style="margin-bottom: 15px; color: #e74c3c;">检测到的威胁 (${securityResult.threats.length} 个)</h5>
                        <div style="display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 20px;">
                            ${securityResult.threats.map(threatType => {
                                return `<span style="padding: 4px 8px; background-color: #e74c3c; color: white; border-radius: 12px; font-size: 12px;">${securityDetector.getThreatDescription(threatType)}</span>`;
                            }).join('')}
                        </div>
                        
                        <div style="margin-top: 20px;">
                            ${securityResult.threats.map(threatType => {
                                const detail = securityResult.details[threatType];
                                return `
                                    <div style="margin-bottom: 20px; padding: 15px; background-color: #fff; border: 1px solid #ddd; border-radius: 6px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);">
                                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                                            <h6 style="margin: 0; color: #e74c3c;">${securityDetector.getThreatDescription(threatType)}</h6>
                                            <span style="padding: 2px 6px; background-color: #f39c12; color: white; border-radius: 10px; font-size: 11px;">${detail.injectionType || '检测到威胁'}</span>
                                        </div>
                                        <p style="margin: 10px 0; color: #666; font-size: 14px;">${detail.description || detail.message}</p>
                                        <div style="margin-top: 10px;">
                                            <strong style="display: block; margin-bottom: 5px; color: #34495e; font-size: 13px;">证据：</strong>
                                            <div style="padding: 8px; background-color: #f5f5f5; border-left: 3px solid #e74c3c; border-radius: 3px; font-family: monospace; font-size: 12px; word-break: break-all;">${detail.evidence}</div>
                                        </div>
                                    </div>
                                `;
                            }).join('')}
                        </div>
                    </div>
                ` : `
                    <div style="padding: 15px; background-color: #e8f5e8; border-radius: 6px; text-align: center;">
                        <p style="color: #2e7d32; font-size: 16px;">🎉 未检测到安全威胁</p>
                        <p style="color: #666; font-size: 14px; margin-top: 5px;">该请求符合安全规范，未发现已知的安全漏洞</p>
                    </div>
                `}
            </div>
            
            <!-- 检测统计 -->
            <div style="margin-bottom: 20px; border: 1px solid #ddd; border-radius: 8px; padding: 15px; background-color: #f9f9f9;">
                <h4 style="margin-bottom: 15px; color: #34495e;">检测统计</h4>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 8px; border: 1px solid #eee; font-weight: bold; background-color: #f5f5f5; font-family: Arial, sans-serif;">检测项目</td>
                        <td style="padding: 8px; border: 1px solid #eee; text-align: center; font-family: Arial, sans-serif;">11项</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border: 1px solid #eee; font-weight: bold; background-color: #f5f5f5; font-family: Arial, sans-serif;">威胁数量</td>
                        <td style="padding: 8px; border: 1px solid #eee; text-align: center; color: ${securityResult.isSecure ? '#2e7d32' : '#e74c3c'}; font-family: Arial, sans-serif;">
                            <strong>${securityResult.isSecure ? '0' : securityResult.threats.length}</strong>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border: 1px solid #eee; font-weight: bold; background-color: #f5f5f5; font-family: Arial, sans-serif;">安全状态</td>
                        <td style="padding: 8px; border: 1px solid #eee; text-align: center; font-family: Arial, sans-serif;">
                            <span style="padding: 4px 12px; background-color: ${securityResult.isSecure ? '#2e7d32' : '#e74c3c'}; color: white; border-radius: 12px; font-size: 13px;">
                                ${securityResult.isSecure ? '安全' : '危险'}
                            </span>
                        </td>
                    </tr>
                </table>
            </div>
            
            <!-- 关闭按钮 -->
            <div style="text-align: center;">
                <button onclick="this.parentElement.parentElement.remove()" style="padding: 10px 20px; background-color: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; transition: background-color 0.2s ease;">
                    关闭
                </button>
            </div>
        </div>
    `;
    
    // 创建弹窗显示安全详情
    const popup = document.createElement('div');
    popup.innerHTML = html;
    popup.style.position = 'fixed';
    popup.style.top = '0';
    popup.style.left = '0';
    popup.style.width = '100%';
    popup.style.height = '100%';
    popup.style.backgroundColor = 'rgba(0, 0, 0, 0.5)';
    popup.style.display = 'flex';
    popup.style.alignItems = 'flex-start'; // 改为顶部对齐，解决顶部看不到的问题
    popup.style.justifyContent = 'center';
    popup.style.zIndex = '10000';
    popup.style.overflowY = 'auto';
    popup.style.padding = '20px';
    popup.style.boxSizing = 'border-box';
    
    // 为关闭按钮添加唯一ID，确保正确关闭
    const closeButton = popup.querySelector('button');
    if (closeButton) {
        closeButton.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            // 确保完全移除弹窗元素，解决阴影残留问题
            while (popup.firstChild) {
                popup.removeChild(popup.firstChild);
            }
            popup.remove();
        });
    }
    
    // 点击弹窗外部关闭
    popup.addEventListener('click', function(e) {
        if (e.target === popup) {
            // 确保完全移除弹窗元素，解决阴影残留问题
            while (popup.firstChild) {
                popup.removeChild(popup.firstChild);
            }
            popup.remove();
        }
    });
    
    // 确保body没有其他弹窗元素
    const existingPopups = document.querySelectorAll('[style*="z-index: 10000"]');
    existingPopups.forEach(existingPopup => {
        if (existingPopup !== popup) {
            existingPopup.remove();
        }
    });
    
    document.body.appendChild(popup);
    
    // 确保弹窗内容可以滚动
    const popupContent = popup.firstElementChild;
    if (popupContent) {
        popupContent.style.maxHeight = '90vh';
        popupContent.style.overflowY = 'auto';
        popupContent.style.boxSizing = 'border-box';
    }
}

// 获取HTTP请求对应的响应数据包
function getHttpResponseForRequest(requestPacket) {
    const requestUniqueId = requestPacket.uniqueId;
    
    // 检查缓存中是否已经有响应
    if (responseCache.has(requestUniqueId)) {
        return responseCache.get(requestUniqueId);
    }
    
    const requestStreamId = requestPacket.streamId;
    const requestTimestamp = requestPacket.timestamp;
    
    // 在同一个流中查找请求之后的响应数据包
    const response = originalPackets.find(packet => {
        return packet.streamId === requestStreamId &&
               packet.timestamp >= requestTimestamp &&
               packet.layers?.application?.protocol === 'HTTP' &&
               packet.layers.application.httpInfo &&
               packet.layers.application.httpInfo.statusCode &&
               packet.layers.application.httpInfo.statusCode !== 'Unknown';
    });
    
    // 将结果缓存
    responseCache.set(requestUniqueId, response);
    
    return response;
}

// 获取非HTTP请求对应的响应数据包
function getNonHttpResponseForRequest(requestPacket) {
    const requestUniqueId = requestPacket.uniqueId;
    const cacheKey = `non-http-${requestUniqueId}`;
    
    // 检查缓存中是否已经有响应
    if (responseCache.has(cacheKey)) {
        return responseCache.get(cacheKey);
    }
    
    const requestStreamId = requestPacket.streamId;
    const requestTimestamp = requestPacket.timestamp;
    const requestIndex = originalPackets.indexOf(requestPacket);
    const appLayer = requestPacket.layers.application;
    
    // 如果没有流ID，尝试在同一个连接中查找响应
    if (!requestStreamId) {
        responseCache.set(cacheKey, null);
        return null;
    }
    
    // 在同一个流中查找请求之后的响应数据包
    const response = originalPackets.find((packet, index) => {
        // 只查找请求之后的数据包
        if (index <= requestIndex) return false;
        
        // 必须是同一个流
        if (packet.streamId !== requestStreamId) return false;
        
        // 必须是应用层数据包
        if (!packet.layers?.application) return false;
        
        // 根据不同协议的特征识别响应
        const packetAppLayer = packet.layers.application;
        
        // DNS协议：响应有isResponse=true
        if (appLayer.dnsInfo && packetAppLayer.dnsInfo) {
            return packetAppLayer.dnsInfo.isResponse === true;
        }
        
        // 其他协议：检查是否有明确的响应标识
        if (packetAppLayer.isResponse) {
            return true;
        }
        
        // TLS/SSL协议：响应通常会有TLS版本和加密套件信息
        if (appLayer.protocol === 'TLS' && packetAppLayer.protocol === 'TLS') {
            // TLS响应通常包含加密套件、TLS版本等信息
            return true;
        }
        
        // 如果没有明确的响应标识，尝试根据时间顺序和协议类型判断
        return packet.timestamp >= requestTimestamp && 
               packet.layers.application.protocol === appLayer.protocol;
    });
    
    // 将结果缓存
    responseCache.set(cacheKey, response);
    
    return response;
}

// 更新HTTP请求URL列表
function updateHttpUrlsList(customPackets = null) {
    // 调用现有的updateAppRequestsList函数，处理HTTP URL列表
    updateAppRequestsList(customPackets);
}

// 更新HTTP请求URL列表
function updateAppRequestsList(customPackets = null) {
    // 检查DOM元素是否存在，避免TypeError
    const tbody = document.getElementById('appRequestsBody');
    const countDiv = document.getElementById('appRequestCount');
    const table = document.querySelector('#appRequestsTable');
    
    // 如果DOM元素不存在，跳过更新（例如页面初始化时或元素尚未加载）
    if (!tbody || !countDiv || !table) {
        return;
    }
    
    // 过滤出所有应用层请求数据包
    let appPackets;
    if (customPackets) {
        // 使用传入的自定义数据包列表
        appPackets = customPackets;
    } else {
        // 从原始数据包中过滤所有应用层请求（只显示请求，不显示响应）
        appPackets = originalPackets.filter(packet => {
            const appLayer = packet.layers?.application;
            if (!appLayer || !appLayer.protocol || appLayer.protocol === 'Unknown') {
                return false;
            }
            
            // 区分不同协议的请求和响应
            if (appLayer.httpInfo) {
                // HTTP协议：请求有method字段，响应有statusCode字段
                return appLayer.httpInfo.method !== undefined && 
                       appLayer.httpInfo.statusCode === undefined;
            } else if (appLayer.dnsInfo) {
                // DNS协议：请求isResponse为false，响应为true
                return appLayer.dnsInfo.isResponse === false || !appLayer.dnsInfo.isResponse;
            } else {
                // 其他协议：检查是否有明确的响应标识
                // 对于其他协议，我们默认只显示带有特定请求特征的包
                // 或者如果没有明确的请求/响应区分，我们只显示第一个包
                return !appLayer.isResponse;
            }
        });
    }
    
    if (appPackets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="19" style="text-align: center; color: #666;">未找到应用层请求</td></tr>';
        countDiv.textContent = '未找到应用层请求';
        return;
    }
    
    // 更新结果计数
    countDiv.textContent = `共计查询到 ${appPackets.length} 条应用层请求`;
    
    // 优化：预计算每个数据包的列值，避免重复计算
    const packetColumnValues = new Map();
    
    // 只有当数据包数量大于1时才需要检查列值是否全部相同
    const allSameColumns = [];
    if (appPackets.length > 1) {
        // 预计算每个数据包的列值
        appPackets.forEach(packet => {
            if (!packetColumnValues.has(packet)) {
                const values = {};
                const isHttp = !!packet.layers.application.httpInfo;
                const httpInfo = isHttp ? packet.layers.application.httpInfo : null;
                
                // 预计算HTTP响应，避免重复调用getHttpResponseForRequest
                const responsePacket = isHttp ? getHttpResponseForRequest(packet) : null;
                
                // 计算各列的值
                values.method = isHttp ? httpInfo.method || '-' : packet.layers.application.protocol || '-';
                values.path = isHttp ? (urlDecode(httpInfo.path || '') || '-') : (packet.layers.application.rawInfo || packet.layers.application.info || '-');
                values.version = isHttp ? httpInfo.version || 'Unknown' : 'Unknown';
                
                const srcPort = packet.layers?.transport?.srcPort || '-';
                values.srcAddr = `${packet.srcIp}:${srcPort}`;
                
                const dstPort = packet.layers?.transport?.dstPort || '-';
                values.dstAddr = `${packet.dstIp}:${dstPort}`;
                
                // 响应相关的列
                if (responsePacket?.layers?.application?.httpInfo?.statusCode) {
                    const statusCode = responsePacket.layers.application.httpInfo.statusCode;
                    const statusText = responsePacket.layers.application.httpInfo.statusText || '';
                    values.responseStatus = `${statusCode} ${statusText}`;
                } else {
                    values.responseStatus = '-';
                }
                
                values.responseSize = responsePacket ? `${responsePacket.packetLen} bytes` : '-';
                
                // HTTP请求头相关的列
                values.host = httpInfo?.headers?.Host || '-';
                values.userAgent = httpInfo?.headers?.['User-Agent'] || '-';
                values.accept = httpInfo?.headers?.Accept || '-';
                values.acceptLanguage = httpInfo?.headers?.['Accept-Language'] || '-';
                values.cookie = httpInfo?.headers?.Cookie || '-';
                values.contentType = httpInfo?.headers?.['Content-Type'] || '-';
                
                // HTTP响应头相关的列
                values.responseContentType = responsePacket?.layers?.application?.httpInfo?.headers?.['Content-Type'] || '-';
                values.server = responsePacket?.layers?.application?.httpInfo?.headers?.Server || '-';
                
                // 响应时间
                values.responseTime = responsePacket ? `${(responsePacket.timestamp - packet.timestamp).toFixed(3)}s` : '-';
                
                // 请求体
                let requestBody = '-';
                if (isHttp && httpInfo?.body && httpInfo.body.length > 0) {
                    requestBody = httpInfo.body;
                    if (requestBody.length > 100) {
                        requestBody = requestBody.substring(0, 100) + '...';
                    }
                } else if (packet.layers.application.raw) {
                    requestBody = packet.layers.application.raw.substring(0, 100) + '...';
                }
                values.requestBody = requestBody;
                
                // 响应体
                let responseBody = '-';
                if (responsePacket?.layers?.application?.httpInfo?.raw) {
                    const rawResponse = responsePacket.layers.application.httpInfo.raw;
                    const parts = rawResponse.split(/\r?\n\r?\n/);
                    if (parts.length > 1) {
                        responseBody = parts.slice(1).join('\r\n\r\n');
                        if (responseBody.length > 100) {
                            responseBody = responseBody.substring(0, 100) + '...';
                        }
                    }
                } else if (responsePacket?.layers?.application?.raw) {
                    responseBody = responsePacket.layers.application.raw.substring(0, 100) + '...';
                }
                values.responseBody = responseBody;
                
                packetColumnValues.set(packet, values);
            }
        });
        
        // 定义列信息，使用预计算的值
        const columns = [
            { name: 'method', index: 1, key: 'method' },
            { name: 'path', index: 2, key: 'path' },
            { name: 'version', index: 3, key: 'version' },
            { name: 'srcAddr', index: 4, key: 'srcAddr' },
            { name: 'dstAddr', index: 5, key: 'dstAddr' },
            { name: 'responseStatus', index: 6, key: 'responseStatus' },
            { name: 'responseSize', index: 7, key: 'responseSize' },
            { name: 'host', index: 8, key: 'host' },
            { name: 'userAgent', index: 9, key: 'userAgent' },
            { name: 'accept', index: 10, key: 'accept' },
            { name: 'acceptLanguage', index: 11, key: 'acceptLanguage' },
            { name: 'cookie', index: 12, key: 'cookie' },
            { name: 'contentType', index: 13, key: 'contentType' },
            { name: 'responseContentType', index: 14, key: 'responseContentType' },
            { name: 'server', index: 15, key: 'server' },
            { name: 'responseTime', index: 16, key: 'responseTime' },
            { name: 'requestBody', index: 17, key: 'requestBody' },
            { name: 'responseBody', index: 18, key: 'responseBody' }
        ];
        
        // 检查每一列的值是否全部相同
        columns.forEach(column => {
            const firstValue = packetColumnValues.get(appPackets[0])[column.key];
            const allValuesSame = appPackets.every(packet => packetColumnValues.get(packet)[column.key] === firstValue);
            
            if (allValuesSame) {
                allSameColumns.push(column);
            }
        });
    }
    
    // 生成列样式
    const getCellStyle = (columnIndex) => {
        const column = allSameColumns.find(col => col.index === columnIndex);
        return column ? 'background-color: #e8f5e8; color: #2e7d32; font-weight: bold;' : '';
    };
    
    // 计算分页数据
    const startIndex = pageSize === Infinity ? 0 : (currentPage - 1) * pageSize;
    const endIndex = pageSize === Infinity ? appPackets.length : startIndex + pageSize;
    const currentPageData = appPackets.slice(startIndex, endIndex);
    
    let html = '';
    currentPageData.forEach((packet, index) => {
        const originalIndex = startIndex + index;
        const srcPort = packet.layers?.transport?.srcPort || '-';
        const dstPort = packet.layers?.transport?.dstPort || '-';
        const srcAddr = `${packet.srcIp}:${srcPort}`;
        const dstAddr = `${packet.dstIp}:${dstPort}`;
        
        // 支持各种应用层协议的请求信息
        const isHttp = !!packet.layers.application.httpInfo;
        const httpInfo = isHttp ? packet.layers.application.httpInfo : null;
        
        // 获取对应的响应数据包
        const responsePacket = isHttp ? getHttpResponseForRequest(packet) : null;
        
        // 提取请求方法或协议名称
        const method = isHttp ? httpInfo.method || '-' : packet.layers.application.protocol || '-';
        
        // 提取路径或信息
        const pathRaw = isHttp ? httpInfo.path || '-' : packet.layers.application.rawInfo || packet.layers.application.info || '-';
        const path = isHttp ? urlDecode(pathRaw) : pathRaw;
        
        // 提取协议版本
        const version = isHttp ? httpInfo.version || 'Unknown' : 'Unknown';
        
        // 提取响应状态
        const responseStatus = responsePacket?.layers?.application?.httpInfo?.statusCode || '-';
        const responseStatusText = responsePacket?.layers?.application?.httpInfo?.statusText || '';
        const responseStatusTextFull = `${responseStatus} ${responseStatusText}`;
        
        // 提取响应大小
        let responseSize = '-';
        let responseSizeFull = '-';
        
        // 对于HTTP协议
        if (isHttp) {
            if (responsePacket) {
                // 如果找到响应数据包，使用其数据包长度
                responseSize = responsePacket.packetLen;
                responseSizeFull = `${responseSize} bytes`;
            } else if (httpInfo.headers?.['Content-Length']) {
                // 如果没有找到响应数据包，但请求头中有Content-Length，显示请求的Content-Length
                responseSize = httpInfo.headers['Content-Length'];
                responseSizeFull = `${responseSize} bytes`;
            }
        } 
        // 对于非HTTP协议（如TLS、DNS等）
        else {
            // 尝试查找对应的响应数据包
            const responsePacketNonHttp = getNonHttpResponseForRequest(packet);
            if (responsePacketNonHttp) {
                // 如果找到响应数据包，使用其数据包长度
                responseSize = responsePacketNonHttp.packetLen;
                responseSizeFull = `${responseSize} bytes`;
            } else {
                // 如果没有找到响应数据包，显示请求本身的大小
                responseSize = packet.packetLen;
                responseSizeFull = `${responseSize} bytes`;
            }
        }
        
        
        // 提取请求头信息（仅HTTP）
        const requestHeaders = isHttp ? httpInfo.headers || {} : {};
        const host = requestHeaders['Host'] || '-';
        const userAgent = requestHeaders['User-Agent'] || '-';
        const cookie = requestHeaders['Cookie'] || '-';
        const contentType = requestHeaders['Content-Type'] || '-';
        const accept = requestHeaders['Accept'] || '-';
        const acceptLanguage = requestHeaders['Accept-Language'] || '-';
        
        // 提取响应头信息（仅HTTP）
        const responseHeaders = responsePacket?.layers?.application?.httpInfo?.headers || {};
        const responseContentType = responseHeaders['Content-Type'] || '-';
        const server = responseHeaders['Server'] || '-';
        const contentLength = responseHeaders['Content-Length'] || '-';
        const responseTime = responsePacket ? (responsePacket.timestamp - packet.timestamp).toFixed(3) + 's' : '-';
        
        // 提取响应体内容
        let responseBody = '-';
        if (responsePacket?.layers?.application?.httpInfo?.body && responsePacket.layers.application.httpInfo.body.length > 0) {
            // 优先使用已经解析好的响应体
            responseBody = responsePacket.layers.application.httpInfo.body;
            // 截断长文本，只显示前100个字符
            if (responseBody.length > 100) {
                responseBody = responseBody.substring(0, 100) + '...';
            }
            // 转义特殊字符
            responseBody = htmlEscape(responseBody);
        } else if (responsePacket?.layers?.application?.httpInfo?.raw) {
            // 备选方案：从raw响应中分割响应体
            const rawResponse = responsePacket.layers.application.httpInfo.raw;
            // 分割响应头和响应体
            const parts = rawResponse.split(/\r?\n\r?\n/);
            if (parts.length > 1) {
                // 获取响应体
                responseBody = parts.slice(1).join('\r\n\r\n');
                // 截断长文本，只显示前100个字符
                if (responseBody.length > 100) {
                    responseBody = responseBody.substring(0, 100) + '...';
                }
                // 转义特殊字符
                responseBody = htmlEscape(responseBody);
            }
        } else if (responsePacket?.layers?.application?.raw) {
            // 非HTTP协议可以使用原始响应数据
            responseBody = responsePacket.layers.application.raw.substring(0, 100) + '...';
            responseBody = htmlEscape(responseBody);
        }
        
        // 提取请求体内容
        let requestBody = '-';
        if (isHttp && httpInfo.body && httpInfo.body.length > 0) {
            requestBody = httpInfo.body;
            if (requestBody.length > 100) {
                requestBody = requestBody.substring(0, 100) + '...';
            }
            requestBody = htmlEscape(requestBody);
        } else if (packet.layers.application.raw) {
            // 非HTTP协议可以使用原始请求数据
            requestBody = packet.layers.application.raw.substring(0, 100) + '...';
            requestBody = htmlEscape(requestBody);
        }
        
        // 解析Cookie信息
        const cookieInfo = cookie ? cookie.split(';').map(c => c.trim()).join('<br>') : '-';
        
        // 执行安全检测
        const securityResult = securityDetector.detect(packet);
        
        // 生成安全检测结果显示
        let securityStatus = '';
        let securityClass = '';
        let securityDetails = '';
        
        if (securityResult.isSecure) {
            securityStatus = '安全';
            securityClass = 'security-safe';
            securityDetails = '未检测到安全威胁';
        } else {
            securityStatus = '危险';
            securityClass = 'security-danger';
            const threatTypes = securityResult.threats.map(type => securityDetector.getThreatDescription(type)).join(', ');
            securityDetails = `检测到：${threatTypes}`;
        }
        
        // 应用高亮
        const highlightedMethod = highlightKeyword(method, currentHttpSearchKeyword);
        const highlightedPath = highlightKeyword(path, currentHttpSearchKeyword);
        const highlightedVersion = highlightKeyword(version, currentHttpSearchKeyword);
        const highlightedSrcAddr = highlightKeyword(srcAddr, currentHttpSearchKeyword);
        const highlightedDstAddr = highlightKeyword(dstAddr, currentHttpSearchKeyword);
        const highlightedResponseStatus = highlightKeyword(responseStatusTextFull, currentHttpSearchKeyword);
        const highlightedResponseSize = highlightKeyword(responseSizeFull, currentHttpSearchKeyword);
        const highlightedHost = highlightKeyword(host, currentHttpSearchKeyword);
        const highlightedUserAgent = highlightKeyword(userAgent, currentHttpSearchKeyword);
        const highlightedAccept = highlightKeyword(accept, currentHttpSearchKeyword);
        const highlightedAcceptLanguage = highlightKeyword(acceptLanguage, currentHttpSearchKeyword);
        const highlightedCookie = highlightKeyword(cookie, currentHttpSearchKeyword);
        const highlightedContentType = highlightKeyword(contentType, currentHttpSearchKeyword);
        const highlightedResponseContentType = highlightKeyword(responseContentType, currentHttpSearchKeyword);
        const highlightedServer = highlightKeyword(server, currentHttpSearchKeyword);
        const highlightedResponseTime = highlightKeyword(responseTime, currentHttpSearchKeyword);
        const highlightedRequestBody = highlightKeyword(requestBody, currentHttpSearchKeyword);
        const highlightedResponseBody = highlightKeyword(responseBody, currentHttpSearchKeyword);
        const highlightedSecurityStatus = highlightKeyword(securityStatus, currentHttpSearchKeyword);
        const highlightedNumber = highlightKeyword((originalIndex + 1).toString(), currentHttpSearchKeyword);
        
        html += `
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">${highlightedNumber}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; ${getCellStyle(1)} text-transform: uppercase; font-weight: 500; color: #2196f3;">${highlightedMethod}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; ${getCellStyle(2)} color: #2c3e50; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${highlightedPath}</td>
                <!-- 隐藏协议版本列 -->
                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; ${getCellStyle(3)}; display: none;">${highlightedVersion}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; ${getCellStyle(4)}">${highlightedSrcAddr}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; ${getCellStyle(5)}">${highlightedDstAddr}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; ${getCellStyle(6)}">${highlightedResponseStatus}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; ${getCellStyle(7)}">${highlightedResponseSize}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; ${getCellStyle(8)} max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${highlightedHost}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; ${getCellStyle(9)} max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${highlightedUserAgent}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; ${getCellStyle(10)} max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${highlightedAccept}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; ${getCellStyle(11)} max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${highlightedAcceptLanguage}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; ${getCellStyle(12)} max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${highlightedCookie}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; ${getCellStyle(13)} max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${highlightedContentType}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; ${getCellStyle(14)} max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${highlightedResponseContentType}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; ${getCellStyle(15)} max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${highlightedServer}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; ${getCellStyle(16)} max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${highlightedResponseTime}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: monospace; font-size: 12px; color: #333; ${getCellStyle(17)} max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${highlightedRequestBody}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: monospace; font-size: 12px; color: #333; ${getCellStyle(18)} max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${highlightedResponseBody}</td>
                <td class="${securityClass}" style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif; font-weight: bold; cursor: help;">${highlightedSecurityStatus}</td>
                <td style="padding: 8px; border: 1px solid #ddd; font-family: Arial, sans-serif;">
                    <div style="display: flex; gap: 5px;">
                        <button onclick="showPacketDetails(${originalPackets.indexOf(packet)})" style="padding: 4px 8px; background-color: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">请求详情</button>
                        ${responsePacket ? `<button onclick="showPacketDetails(${originalPackets.indexOf(responsePacket)})" style="padding: 4px 8px; background-color: #2ecc71; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">响应详情</button>` : ''}
                        <button onclick="showSecurityDetails(${originalIndex})" style="padding: 4px 8px; background-color: #95a5a6; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">安全详情</button>
                        ${responsePacket && (responseHeaders['Content-Type'] || '').match(/(application\/octet-stream|application\/pdf|image\/|audio\/|video\/|application\/zip|application\/rar|application\/msword|application\/vnd\.|application\/json|text\/|text\/html|application\/xml)/i) ? `<button onclick="downloadHttpResponse(${originalPackets.indexOf(responsePacket)})" style="padding: 4px 8px; background-color: #f39c12; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px;">下载文件</button>` : ''}
                    </div>
                </td>
            </tr>`;
        
        // 将安全检测结果保存到数据包对象中，用于后续查看详情
        packet.securityResult = securityResult;
    });
    
    tbody.innerHTML = html;
    
    // 为表头添加样式
    if (table) {
        const headers = table.querySelectorAll('thead th');
        headers.forEach((header, index) => {
            const column = allSameColumns.find(col => col.index === index);
            if (column) {
                header.style.backgroundColor = '#c8e6c9';
                header.style.color = '#1b5e20';
                header.style.fontWeight = 'bold';
            } else {
                header.style.backgroundColor = '';
                header.style.color = '';
                header.style.fontWeight = '';
            }
        });
    }
    
    // 更新分页信息
    if (currentListType === 'appRequests') {
        updatePagination();
    }
    
    // 重新初始化表格拖拽功能和筛选功能
    reinitTableResizable();
}

// 搜索HTTP请求URL
function searchAppRequests() {
    // 检查是否已选择文件
    if (originalPackets.length === 0) {
        // 弹出自定义提示
        showCustomAlert('请选择文件');
        return;
    }
    
    // 检查DOM元素是否存在，避免TypeError
    const appRequestSearch = document.getElementById('appRequestSearch');
    const appRequestFilterType = document.getElementById('appRequestFilterType');
    const tbody = document.getElementById('appRequestsBody');
    const countDiv = document.getElementById('appRequestCount');
    const table = document.querySelector('#appRequestsTable');
    
    // 如果DOM元素不存在，跳过搜索（例如页面初始化时或元素尚未加载）
    if (!appRequestSearch || !appRequestFilterType || !tbody || !countDiv || !table) {
        return;
    }
    
    currentHttpSearchKeyword = appRequestSearch.value;
    // 确保searchText是字符串类型
    const searchText = String(currentHttpSearchKeyword).toLowerCase();
    const filterType = appRequestFilterType.value;
    
    // 过滤出所有应用层请求数据包（只显示请求，不显示响应）
    let appPackets = originalPackets.filter(packet => {
        const appLayer = packet.layers?.application;
        if (!appLayer || !appLayer.protocol || appLayer.protocol === 'Unknown') {
            return false;
        }
        
        // 区分不同协议的请求和响应
        if (appLayer.httpInfo) {
            // HTTP协议：请求有method字段，响应有statusCode字段
            return appLayer.httpInfo.method !== undefined && 
                   appLayer.httpInfo.statusCode === undefined;
        } else if (appLayer.dnsInfo) {
            // DNS协议：请求isResponse为false，响应为true
            return appLayer.dnsInfo.isResponse === false || !appLayer.dnsInfo.isResponse;
        } else {
            // 其他协议：检查是否有明确的响应标识
            // 对于其他协议，我们默认只显示带有特定请求特征的包
            // 或者如果没有明确的请求/响应区分，我们只显示第一个包
            return !appLayer.isResponse;
        }
    });
    
    if (searchText.trim()) {
        appPackets = appPackets.filter(packet => {
            const httpInfo = packet.layers.application.httpInfo;
            const srcAddr = `${packet.srcIp}:${packet.layers?.transport?.srcPort || '-'}`;
            const dstAddr = `${packet.dstIp}:${packet.layers?.transport?.dstPort || '-'}`;
            
            // 初始化变量，处理非HTTP协议的情况
            let path = '';
            let method = '';
            let version = '';
            let host = '';
            let userAgent = '';
            let accept = '';
            let acceptLanguage = '';
            let cookie = '';
            let contentType = '';
            let requestDetails = '';
            let responseStatus = '';
            let responseSize = '';
            let responseContentType = '';
            let server = '';
            let responseTime = '';
            let responseDetails = '';
            
            // 提取响应信息用于搜索
            const responsePacket = httpInfo ? getHttpResponseForRequest(packet) : null;
            
            if (httpInfo) {
                // HTTP协议处理
                path = httpInfo.path || '';
                method = httpInfo.method || '';
                version = httpInfo.httpVersion || '';
                
                // 提取请求头信息用于搜索
                const requestHeaders = httpInfo.headers || {};
                host = requestHeaders['Host'] || '';
                userAgent = requestHeaders['User-Agent'] || '';
                accept = requestHeaders['Accept'] || '';
                acceptLanguage = requestHeaders['Accept-Language'] || '';
                cookie = requestHeaders['Cookie'] || '';
                contentType = requestHeaders['Content-Type'] || '';
                
                if (responsePacket?.layers?.application?.httpInfo?.statusCode) {
                    const statusCode = responsePacket.layers.application.httpInfo.statusCode;
                    const statusText = responsePacket.layers.application.httpInfo.statusText || '';
                    responseStatus = `${statusCode} ${statusText}`;
                }
                responseSize = responsePacket ? responsePacket.packetLen.toString() : '';
                const responseHeaders = responsePacket?.layers?.application?.httpInfo?.headers || {};
                responseContentType = responseHeaders['Content-Type'] || '';
                server = responseHeaders['Server'] || '';
                responseTime = responsePacket ? (responsePacket.timestamp - packet.timestamp).toFixed(3) : '';
                
                // 提取请求详情和响应详情
                requestDetails = httpInfo.raw || httpInfo.body || '';
                responseDetails = responsePacket?.layers?.application?.httpInfo?.raw || 
                              responsePacket?.layers?.application?.httpInfo?.body || '';
            } else {
                // 非HTTP协议处理
                method = packet.layers.application.protocol || '';
                requestDetails = packet.layers.application.rawInfo || packet.layers.application.info || '';
            }
            
            // 创建HTTP请求信息对象
            const httpUrlInfo = {
                method: method.toLowerCase(),
                path: path.toLowerCase(),
                version: version.toLowerCase(),
                srcAddr: srcAddr.toLowerCase(),
                dstAddr: dstAddr.toLowerCase(),
                responseStatus: responseStatus.toLowerCase(),
                responseSize: responseSize.toLowerCase(),
                host: host.toLowerCase(),
                userAgent: userAgent.toLowerCase(),
                accept: accept.toLowerCase(),
                acceptLanguage: acceptLanguage.toLowerCase(),
                cookie: cookie.toLowerCase(),
                contentType: contentType.toLowerCase(),
                responseContentType: responseContentType.toLowerCase(),
                server: server.toLowerCase(),
                responseTime: responseTime.toLowerCase(),
                requestDetails: requestDetails.toLowerCase(),
                responseDetails: responseDetails.toLowerCase(),
                requestBody: (httpInfo?.body || '').toLowerCase(),
                responseBody: (responsePacket?.layers?.application?.httpInfo?.body || '').toLowerCase()
            };
            
            // 检查是否匹配搜索文本
            let matchesSearch = false;
            
            if (filterType === 'all') {
                // 搜索所有字段
                matchesSearch = Object.values(httpUrlInfo).some(value => value.includes(searchText));
            } else {
                // 搜索特定字段
                matchesSearch = httpUrlInfo[filterType].includes(searchText);
            }
            
            return matchesSearch;
        });
    }
    
    // 应用筛选条件
    const tableFilters = filters['appRequestsTable'] || {};
    if (Object.keys(tableFilters).length > 0) {
        appPackets = appPackets.filter(packet => {
            let matchesAll = true;
            
            // 遍历所有筛选条件
            for (const [columnIndex, values] of Object.entries(tableFilters)) {
                const colIndex = parseInt(columnIndex);
                let value;
                
                // 获取httpInfo（可能为undefined，例如非HTTP协议）
                const httpInfo = packet.layers.application.httpInfo;
                
                // 根据列索引获取值
                switch(colIndex) {
                    case 1: // 请求方法
                        value = httpInfo ? (httpInfo.method || '-') : packet.layers.application.protocol || '-';
                        break;
                    case 2: // URL路径或信息
                        value = httpInfo ? (urlDecode(httpInfo.path || '') || '-') : (packet.layers.application.rawInfo || packet.layers.application.info || '-');
                        break;
                    case 3: // 协议版本
                        value = httpInfo ? (httpInfo.version || 'Unknown') : 'Unknown';
                        break;
                    case 4: // 源IP:端口
                        value = `${packet.srcIp}:${packet.layers?.transport?.srcPort || '-'}`;
                        break;
                    case 5: // 目标IP:端口
                        value = `${packet.dstIp}:${packet.layers?.transport?.dstPort || '-'}`;
                        break;
                    case 6: { // 响应状态
                        if (!httpInfo) {
                            value = '-';
                            break;
                        }
                        const responsePacket = getHttpResponseForRequest(packet);
                        value = responsePacket?.layers?.application?.httpInfo?.statusCode ? `${responsePacket.layers.application.httpInfo.statusCode} ${responsePacket.layers.application.httpInfo.statusText}` : '-';
                        break;
                    }
                    case 7: { // 响应大小
                        const isHttp = !!httpInfo;
                        let responseSizeFull = '-';
                        
                        if (isHttp) {
                            // HTTP协议处理
                            const responsePacket = getHttpResponseForRequest(packet);
                            if (responsePacket) {
                                responseSizeFull = `${responsePacket.packetLen} bytes`;
                            } else if (httpInfo.headers?.['Content-Length']) {
                                responseSizeFull = `${httpInfo.headers['Content-Length']} bytes`;
                            }
                        } else {
                            // 非HTTP协议处理
                            const responsePacketNonHttp = getNonHttpResponseForRequest(packet);
                            if (responsePacketNonHttp) {
                                responseSizeFull = `${responsePacketNonHttp.packetLen} bytes`;
                            } else {
                                responseSizeFull = `${packet.packetLen} bytes`;
                            }
                        }
                        value = responseSizeFull;
                        break;
                    }
                    case 8: // Host
                        value = httpInfo?.headers?.Host || '-';
                        break;
                    case 9: // User-Agent
                        value = httpInfo?.headers?.['User-Agent'] || '-';
                        break;
                    case 10: // Accept
                        value = httpInfo?.headers?.Accept || '-';
                        break;
                    case 11: // Accept-Language
                        value = httpInfo?.headers?.['Accept-Language'] || '-';
                        break;
                    case 12: // Cookie
                        value = httpInfo?.headers?.Cookie || '-';
                        break;
                    case 13: // Content-Type
                        value = httpInfo?.headers?.['Content-Type'] || '-';
                        break;
                    case 14: { // 响应内容类型
                        if (!httpInfo) {
                            value = '-';
                            break;
                        }
                        const responsePacket = getHttpResponseForRequest(packet);
                        // 允许部分匹配，例如当筛选值为'application/octet-stream'时，匹配'application/octet-stream; charset=utf-8'
                        const contentType = responsePacket?.layers?.application?.httpInfo?.headers?.['Content-Type'] || '-';
                        // 提取主类型和子类型，忽略参数
                        value = contentType.split(';')[0].trim() || '-';
                        break;
                    }
                    case 15: { // 服务器
                        if (!httpInfo) {
                            value = '-';
                            break;
                        }
                        const responsePacket = getHttpResponseForRequest(packet);
                        value = responsePacket?.layers?.application?.httpInfo?.headers?.Server || '-';
                        break;
                    }
                    case 16: { // 响应时间
                        if (!httpInfo) {
                            value = '-';
                            break;
                        }
                        const responsePacket = getHttpResponseForRequest(packet);
                        value = responsePacket ? `${(responsePacket.timestamp - packet.timestamp).toFixed(3)}s` : '-';
                        break;
                    }
                    case 17: { // 请求体内容
                        if (!httpInfo) {
                            value = '-';
                            break;
                        }
                        let requestBody = httpInfo.body || '-';
                        if (requestBody && requestBody.length > 50) {
                            requestBody = requestBody.substring(0, 50) + '...';
                        }
                        value = requestBody;
                        break;
                    }
                    case 18: { // 响应体内容
                        if (!httpInfo) {
                            value = '-';
                            break;
                        }
                        const responsePacket = getHttpResponseForRequest(packet);
                        let responseBody = '-';
                        if (responsePacket?.layers?.application?.httpInfo?.raw) {
                            const rawResponse = responsePacket.layers.application.httpInfo.raw;
                            const parts = rawResponse.split(/\r?\n\r?\n/);
                            if (parts.length > 1) {
                                responseBody = parts.slice(1).join('\r\n\r\n');
                                if (responseBody.length > 50) {
                                    responseBody = responseBody.substring(0, 50) + '...';
                                }
                            }
                        }
                        value = responseBody;
                        break;
                    }
                    case 19: { // 安全状态
                        // 安全状态 - 执行安全检测获取状态
                        const securityResult = securityDetector.detect(packet);
                        value = securityResult.isSecure ? '安全' : '危险';
                        break;
                    }
                    default: continue; // 跳过其他列
                }
                
                // 检查值是否匹配筛选条件
                // 对于响应内容类型，允许部分匹配，例如当筛选值为'application/octet-stream'时，匹配'application/octet-stream; charset=utf-8'
                // 对于其他字段，使用精确匹配
                const matches = values.some(filterValue => {
                    // 如果筛选值是'-'，则匹配所有值为'-'的项
                    if (filterValue === '-') {
                        return value === '-';
                    }
                    // 对于响应内容类型列（第14列），允许部分匹配
                    if (colIndex === 14) {
                        return value.includes(filterValue);
                    }
                    // 对于其他列，使用精确匹配
                    return value === filterValue;
                });
                
                if (!matches) {
                    matchesAll = false;
                    break;
                }
            }
            
            return matchesAll;
        });
    }
    
    // 应用排序逻辑
    if (currentHttpSortField) {
        appPackets.sort((a, b) => {
            let aValue, bValue;
            
            // 根据排序字段获取值
            switch(currentHttpSortField) {
                case 'index':
                    aValue = a.uniqueId;
                    bValue = b.uniqueId;
                    break;
                case 'method':
                    // 支持各种应用层协议的请求方法
                    if (a.layers.application.httpInfo) {
                        aValue = a.layers.application.httpInfo.method || '';
                    } else {
                        // 非HTTP协议可以使用协议名称或其他标识
                        aValue = a.layers.application.protocol || '';
                    }
                    if (b.layers.application.httpInfo) {
                        bValue = b.layers.application.httpInfo.method || '';
                    } else {
                        // 非HTTP协议可以使用协议名称或其他标识
                        bValue = b.layers.application.protocol || '';
                    }
                    break;
                case 'path':
                    // 支持各种应用层协议的路径或标识符
                    if (a.layers.application.httpInfo) {
                        aValue = urlDecode(a.layers.application.httpInfo.path || '') || '';
                    } else {
                        // 非HTTP协议可以使用信息字段或其他标识
                        aValue = a.layers.application.rawInfo || a.layers.application.info || '';
                    }
                    if (b.layers.application.httpInfo) {
                        bValue = urlDecode(b.layers.application.httpInfo.path || '') || '';
                    } else {
                        // 非HTTP协议可以使用信息字段或其他标识
                        bValue = b.layers.application.rawInfo || b.layers.application.info || '';
                    }
                    break;
                case 'version':
                    // 支持各种应用层协议的版本
                    if (a.layers.application.httpInfo) {
                        aValue = a.layers.application.httpInfo.version || 'Unknown';
                    } else {
                        aValue = 'Unknown';
                    }
                    if (b.layers.application.httpInfo) {
                        bValue = b.layers.application.httpInfo.version || 'Unknown';
                    } else {
                        bValue = 'Unknown';
                    }
                    break;
                case 'srcAddr':
                    aValue = `${a.srcIp}:${a.layers?.transport?.srcPort || '-'}`;
                    bValue = `${b.srcIp}:${b.layers?.transport?.srcPort || '-'}`;
                    break;
                case 'dstAddr':
                    aValue = `${a.dstIp}:${a.layers?.transport?.dstPort || '-'}`;
                    bValue = `${b.dstIp}:${b.layers?.transport?.dstPort || '-'}`;
                    break;
                case 'responseStatus':
                    // 支持各种应用层协议的响应状态
                    const aResponsePacket = getHttpResponseForRequest(a);
                    const bResponsePacket = getHttpResponseForRequest(b);
                    aValue = aResponsePacket?.layers?.application?.httpInfo?.statusCode || 0;
                    bValue = bResponsePacket?.layers?.application?.httpInfo?.statusCode || 0;
                    break;
                case 'responseSize':
                    // 对于HTTP请求，优先使用响应包大小，其次使用Content-Length头部
                    // 对于非HTTP请求，优先使用响应包大小，其次使用请求包大小
                    const getResponseSize = (packet) => {
                        const httpInfo = packet.layers.application.httpInfo;
                        const isHttp = !!httpInfo;
                        
                        if (isHttp) {
                            const responsePacket = getHttpResponseForRequest(packet);
                            if (responsePacket) {
                                return responsePacket.packetLen || 0;
                            } else if (httpInfo.headers?.['Content-Length']) {
                                return parseInt(httpInfo.headers['Content-Length']) || 0;
                            }
                        } else {
                            const responsePacketNonHttp = getNonHttpResponseForRequest(packet);
                            if (responsePacketNonHttp) {
                                return responsePacketNonHttp.packetLen || 0;
                            } else {
                                return packet.packetLen || 0;
                            }
                        }
                        return 0;
                    };
                    aValue = getResponseSize(a);
                    bValue = getResponseSize(b);
                    break;
                case 'host':
                    // 仅HTTP协议有Host头
                    aValue = a.layers.application.httpInfo?.headers?.Host || '';
                    bValue = b.layers.application.httpInfo?.headers?.Host || '';
                    break;
                case 'userAgent':
                    // 仅HTTP协议有User-Agent头
                    aValue = a.layers.application.httpInfo?.headers?.['User-Agent'] || '';
                    bValue = b.layers.application.httpInfo?.headers?.['User-Agent'] || '';
                    break;
                case 'accept':
                    // 仅HTTP协议有Accept头
                    aValue = a.layers.application.httpInfo?.headers?.Accept || '';
                    bValue = b.layers.application.httpInfo?.headers?.Accept || '';
                    break;
                case 'acceptLanguage':
                    // 仅HTTP协议有Accept-Language头
                    aValue = a.layers.application.httpInfo?.headers?.['Accept-Language'] || '';
                    bValue = b.layers.application.httpInfo?.headers?.['Accept-Language'] || '';
                    break;
                case 'cookie':
                    // 仅HTTP协议有Cookie头
                    aValue = a.layers.application.httpInfo?.headers?.Cookie || '';
                    bValue = b.layers.application.httpInfo?.headers?.Cookie || '';
                    break;
                case 'contentType':
                    // 仅HTTP协议有Content-Type头
                    aValue = a.layers.application.httpInfo?.headers?.['Content-Type'] || '';
                    bValue = b.layers.application.httpInfo?.headers?.['Content-Type'] || '';
                    break;
                case 'responseContentType':
                    // 仅HTTP协议响应有Content-Type头
                    aValue = getHttpResponseForRequest(a)?.layers?.application?.httpInfo?.headers?.['Content-Type'] || '';
                    bValue = getHttpResponseForRequest(b)?.layers?.application?.httpInfo?.headers?.['Content-Type'] || '';
                    break;
                case 'server':
                    // 仅HTTP协议响应有Server头
                    aValue = getHttpResponseForRequest(a)?.layers?.application?.httpInfo?.headers?.Server || '';
                    bValue = getHttpResponseForRequest(b)?.layers?.application?.httpInfo?.headers?.Server || '';
                    break;
                case 'responseTime':
                    const aResponse = getHttpResponseForRequest(a);
                    const bResponse = getHttpResponseForRequest(b);
                    aValue = aResponse ? (aResponse.timestamp - a.timestamp) : 0;
                    bValue = bResponse ? (bResponse.timestamp - b.timestamp) : 0;
                    break;
                default:
                    aValue = '';
                    bValue = '';
            }
            
            // 根据值类型进行比较
            let comparison;
            if (typeof aValue === 'number' && typeof bValue === 'number') {
                comparison = aValue - bValue;
            } else {
                comparison = String(aValue).localeCompare(String(bValue));
            }
            
            // 根据排序方向调整结果
            return currentHttpSortDirection === 'asc' ? comparison : -comparison;
        });
    }
    
    // 保存排序后的数据包
    sortedHttpPackets = appPackets;
    
    // 调用updateAppRequestsList函数并传递过滤后的数据包列表，这样可以复用已经实现的高亮功能
    currentListType = 'appRequests'; // 设置当前列表类型
    updateAppRequestsList(appPackets);
}

// 清除HTTP请求URL搜索
function clearAppRequestSearch() {
    document.getElementById('appRequestSearch').value = '';
    currentHttpSearchKeyword = '';
    updateAppRequestsList();
}

// HTTP请求URL列表排序函数
let currentHttpSortField = null;
let currentHttpSortDirection = 'asc'; // 'asc' 或 'desc'
let sortedHttpPackets = []; // 保存排序后的HTTP数据包

function sortAppRequests(field) {
    // 切换排序方向
    if (currentHttpSortField === field) {
        currentHttpSortDirection = currentHttpSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        currentHttpSortField = field;
        currentHttpSortDirection = 'asc';
    }
    
    // 直接调用searchAppRequests函数，它会处理搜索、筛选和排序
    searchAppRequests();
}

// 导出应用层请求列表为XLSX
function exportAppRequestsToXLSX() {
    // 使用当前显示的应用层请求数据（包含搜索、筛选和排序后的结果）
    let appPackets = sortedHttpPackets;
    
    // 如果sortedHttpPackets为空，则使用原始数据
    if (!appPackets || appPackets.length === 0) {
        appPackets = originalPackets.filter(packet => {
            const appLayer = packet.layers?.application;
            if (!appLayer || !appLayer.protocol || appLayer.protocol === 'Unknown') {
                return false;
            }
            
            // 区分不同协议的请求和响应
            if (appLayer.httpInfo) {
                // HTTP协议：请求有method字段，响应有statusCode字段
                return appLayer.httpInfo.method !== undefined && 
                       appLayer.httpInfo.statusCode === undefined;
            } else if (appLayer.dnsInfo) {
                // DNS协议：请求isResponse为false，响应为true
                return appLayer.dnsInfo.isResponse === false || !appLayer.dnsInfo.isResponse;
            } else {
                // 其他协议：检查是否有明确的响应标识
                // 对于其他协议，我们默认只显示带有特定请求特征的包
                // 或者如果没有明确的请求/响应区分，我们只显示第一个包
                return !appLayer.isResponse;
            }
        });
    }
    
    if (appPackets.length === 0) {
        alert('没有应用层请求可导出');
        return;
    }
    
    // 定义XLSX列标题
    const headers = [
        '序号', '请求方法/协议', '路径/信息', '协议版本', '源IP:端口', '目标IP:端口',
        '响应状态', '响应大小', 'Host', 'User-Agent', 'Accept', 'Accept-Language',
        'Cookie', 'Content-Type', '响应内容类型', '服务器', '响应时间', '请求体内容', '响应体内容'
    ];
    
    // 定义XLSX数据行
    const rows = appPackets.map((packet, index) => {
        const isHttp = !!packet.layers.application.httpInfo;
        const httpInfo = isHttp ? packet.layers.application.httpInfo : null;
        const srcPort = packet.layers?.transport?.srcPort || '-';
        const dstPort = packet.layers?.transport?.dstPort || '-';
        const srcAddr = `${packet.srcIp}:${srcPort}`;
        const dstAddr = `${packet.dstIp}:${dstPort}`;
        
        // 提取方法或协议名称
        const method = isHttp ? httpInfo.method || '-' : packet.layers.application.protocol || '-';
        
        // 提取路径或信息
        const pathRaw = isHttp ? httpInfo.path || '-' : (packet.layers.application.rawInfo || packet.layers.application.info || '-');
        const path = isHttp ? urlDecode(pathRaw) : pathRaw;
        
        // 提取协议版本
        const version = isHttp ? httpInfo.version || 'Unknown' : 'Unknown';
        
        // 获取对应的响应数据包（仅HTTP）
        const responsePacket = isHttp ? getHttpResponseForRequest(packet) : null;
        const responseStatus = responsePacket?.layers.application.httpInfo.statusCode || '-';
        const responseStatusText = responsePacket?.layers.application.httpInfo.statusText || '';
        const responseSize = responsePacket?.packetLen || '-';
        const responseHeaders = responsePacket?.layers.application.httpInfo.headers || {};
        
        // 提取请求头信息（仅HTTP）
        const requestHeaders = isHttp ? httpInfo.headers || {} : {};
        const host = requestHeaders['Host'] || '-';
        const userAgent = requestHeaders['User-Agent'] || '-';
        const cookie = requestHeaders['Cookie'] || '-';
        const contentType = requestHeaders['Content-Type'] || '-';
        const accept = requestHeaders['Accept'] || '-';
        const acceptLanguage = requestHeaders['Accept-Language'] || '-';
        
        // 提取响应头信息（仅HTTP）
        const responseContentType = responseHeaders['Content-Type'] || '-';
        const server = responseHeaders['Server'] || '-';
        const responseTime = responsePacket ? (responsePacket.timestamp - packet.timestamp).toFixed(3) + 's' : '-';
        
        // 提取请求体内容
        let requestBody = '-';
        if (isHttp && httpInfo.body) {
            requestBody = httpInfo.body;
        } else if (packet.layers.application.raw) {
            requestBody = packet.layers.application.raw;
        }
        
        // 提取响应体内容
        let responseBody = '-';
        if (responsePacket?.layers.application?.httpInfo?.raw) {
            const rawResponse = responsePacket.layers.application.httpInfo.raw;
            const parts = rawResponse.split(/\r?\n\r?\n/);
            if (parts.length > 1) {
                responseBody = parts.slice(1).join('\r\n\r\n');
            }
        } else if (responsePacket?.layers.application?.raw) {
            responseBody = responsePacket.layers.application.raw;
        }
        
        return {
            '序号': index + 1,
            '请求方法/协议': method,
            '路径/信息': path,
            '协议版本': version,
            '源IP:端口': srcAddr,
            '目标IP:端口': dstAddr,
            '响应状态': `${responseStatus} ${responseStatusText}`.trim(),
            '响应大小': responseSize,
            'Host': host,
            'User-Agent': userAgent,
            'Accept': accept,
            'Accept-Language': acceptLanguage,
            'Cookie': cookie,
            'Content-Type': contentType,
            '响应内容类型': responseContentType,
            '服务器': server,
            '响应时间': responseTime,
            '请求体内容': requestBody,
            '响应体内容': responseBody
        };
    });
    
    // 创建工作簿
    const wb = XLSX.utils.book_new();
    
    // 创建工作表
    const ws = XLSX.utils.json_to_sheet(rows, { header: headers });
    
    // 设置列宽
    const colWidths = [
        { wch: 8 }, // 序号
        { wch: 15 }, // 请求方法/协议
        { wch: 30 }, // 路径/信息
        { wch: 12 }, // 协议版本
        { wch: 20 }, // 源IP:端口
        { wch: 20 }, // 目标IP:端口
        { wch: 15 }, // 响应状态
        { wch: 10 }, // 响应大小
        { wch: 20 }, // Host
        { wch: 30 }, // User-Agent
        { wch: 20 }, // Accept
        { wch: 20 }, // Accept-Language
        { wch: 30 }, // Cookie
        { wch: 20 }, // Content-Type
        { wch: 20 }, // 响应内容类型
        { wch: 20 }, // 服务器
        { wch: 12 }, // 响应时间
        { wch: 50 }, // 请求体内容
        { wch: 50 } // 响应体内容
    ];
    ws['!cols'] = colWidths;
    
    // 添加工作表到工作簿
    XLSX.utils.book_append_sheet(wb, ws, '应用层请求列表');
    
    // 导出为XLSX文件
    XLSX.writeFile(wb, `app_requests_${new Date().getTime()}.xlsx`);
}

function formatFileSize(bytes) {
    if (bytes < 1024) {
        return bytes + ' B';
    } else if (bytes < 1024 * 1024) {
        return (bytes / 1024).toFixed(2) + ' KB';
    } else {
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    }
}

// 确保handleFileUpload函数在全局作用域中可用
if (typeof window !== 'undefined') {
    window.handleFileUpload = handleFileUpload;
    
    // 调试代码：检查handleFileUpload函数是否被正确定义
    console.log('app.js loaded');
    console.log('handleFileUpload function:', typeof handleFileUpload);
    console.log('window.handleFileUpload function:', typeof window.handleFileUpload);
} else {
    // 在非浏览器环境中，将handleFileUpload函数导出，便于测试
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = {
            detectDeviceInfo,
            handleFileUpload
        };
    }
}

// 分页核心函数

// 获取当前列表数据
function getCurrentList() {
    switch (currentListType) {
        case 'packets':
            return currentPackets;
        case 'streams':
            return Object.values(currentStreams);
        case 'appRequests':
            return originalPackets.filter(packet => {
                return packet.layers?.application && 
                       packet.layers.application.protocol &&
                       packet.layers.application.protocol !== 'Unknown';
            });
        default:
            return [];
    }
}

// 设置当前列表类型
function setCurrentListType(listType) {
    currentListType = listType;
    currentPage = 1; // 切换列表类型时重置到第一页
    updateListWithPagination();
}

// 切换分页大小
function changePageSize() {
    const newPageSize = document.getElementById('pageSize').value;
    pageSize = newPageSize === 'all' ? Infinity : parseInt(newPageSize);
    currentPage = 1; // 切换每页显示数量时重置到第一页
    updateListWithPagination();
}

// 上一页
function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        updateListWithPagination();
    }
}

// 下一页
function nextPage() {
    if (currentPage < totalPages) {
        currentPage++;
        updateListWithPagination();
    }
}

// 更新列表数据（带分页）
function updateListWithPagination() {
    const list = getCurrentList();
    totalPages = pageSize === Infinity ? 1 : Math.ceil(list.length / pageSize);
    
    // 确保当前页码在有效范围内
    if (currentPage > totalPages) {
        currentPage = totalPages;
    }
    
    // 更新分页控件
    updatePagination();
    
    // 更新对应列表
    switch (currentListType) {
        case 'packets':
            updatePacketsList(currentPackets);
            break;
        case 'streams':
            updateStreamsList(currentStreams);
            break;
        case 'appRequests':
            const searchText = document.getElementById('appRequestSearch').value;
            if (searchText.trim()) {
                searchAppRequests();
            } else {
                updateAppRequestsList();
            }
            break;
    }
}

// 更新分页控件状态
function updatePagination() {
    const list = getCurrentList();
    const totalItems = list.length;
    let startItem, endItem;
    
    // 处理pageSize为Infinity的情况
    if (pageSize === Infinity) {
        startItem = 1;
        endItem = totalItems;
    } else {
        startItem = (currentPage - 1) * pageSize + 1;
        endItem = Math.min(currentPage * pageSize, totalItems);
    }
    
    // 更新页码信息
    document.getElementById('pageInfo').textContent = `第 ${currentPage} 页 / 共 ${totalPages} 页 (${startItem}-${endItem} / ${totalItems} 条)`;
    
    // 更新按钮状态
    document.getElementById('prevPage').disabled = currentPage === 1;
    document.getElementById('nextPage').disabled = currentPage === totalPages;
}

// 显示自定义提示框
function showCustomAlert(message, duration = 3000) {
    const alertElement = document.getElementById('customAlert');
    const contentElement = document.getElementById('customAlertContent');
    
    // 设置提示内容
    contentElement.textContent = message;
    
    // 显示提示框
    alertElement.style.opacity = '1';
    alertElement.style.visibility = 'visible';
    alertElement.style.transform = 'translateX(-50%) translateY(0)';
    
    // 一段时间后自动隐藏
    setTimeout(() => {
        alertElement.style.opacity = '0';
        alertElement.style.visibility = 'hidden';
        alertElement.style.transform = 'translateX(-50%) translateY(-100px)';
    }, duration);
}

// 切换标签时更新列表类型
function switchTab(tabName) {
    // 检查是否已选择文件，除了概览和设置页面，其他页面需要文件
    if (originalPackets.length === 0 && tabName !== 'overview' && tabName !== 'settings') {
        // 弹出自定义提示
        showCustomAlert('请选择文件');
        return;
    }
    
    // 移除所有标签的active类
    const tabBtns = document.querySelectorAll('.tab-btn');
    tabBtns.forEach(btn => btn.classList.remove('active'));
    
    // 隐藏所有标签内容
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(content => content.classList.remove('active'));
    
    // 激活当前标签
    document.querySelector(`[onclick="switchTab('${tabName}')"]`).classList.add('active');
    document.getElementById(tabName).classList.add('active');
    
    // 显示或隐藏分页控件
    const pagination = document.getElementById('pagination');
    if (pagination) {
        // 概览、数据包详情、IP端口统计、连接频率统计和设置页面不显示分页控件
        if (tabName === 'overview' || tabName === 'details' || tabName === 'ipPortStats' || tabName === 'connectionStats' || tabName === 'settings') {
            pagination.style.display = 'none';
        } else {
            pagination.style.display = 'flex';
        }
    }
    
    // 如果切换到设置标签，更新关键字列表
    if (tabName === 'settings') {
        updateKeywordList();
    }
    
    // 根据标签设置当前列表类型
    switch (tabName) {
        case 'packets':
            setCurrentListType('packets');
            break;
        case 'flows':
            setCurrentListType('streams');
            break;
        case 'appRequests':
            setCurrentListType('appRequests');
            break;
        default:
            // 其他标签不需要分页
            break;
    }
}

// 添加复制事件监听器，确保复制完整的HTTP响应内容
document.addEventListener('copy', function(e) {
    const selection = window.getSelection();
    if (!selection.rangeCount) return;
    
    const range = selection.getRangeAt(0);
    const cell = range.commonAncestorContainer.closest('td[data-full-content]');
    
    if (cell) {
        // 获取完整内容
        const fullContent = cell.getAttribute('data-full-content');
        if (fullContent) {
            e.clipboardData.setData('text/plain', fullContent);
            e.preventDefault();
        }
    }
});