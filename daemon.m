#import <Foundation/Foundation.h>
#import <sqlite3.h>
#import <CommonCrypto/CommonDigest.h>
#import <fcntl.h>
#import <signal.h>
#import <spawn.h>
#import <sys/event.h>
#import <sys/stat.h>
#import <sys/time.h>
#import <sys/wait.h>
#import <unistd.h>

extern int responsibility_spawnattrs_setdisclaim(posix_spawnattr_t *attrs, int disclaim) __attribute__((weak_import));

static volatile sig_atomic_t gShouldTerminate = 0;

static void handleSignal(int sig) {
    (void)sig;
    gShouldTerminate = 1;
}

static BOOL parseBoolValue(NSString *val, BOOL defaultVal) {
    if (!val || val.length == 0) return defaultVal;
    NSString *low = [[val stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] lowercaseString];
    if ([low isEqualToString:@"1"] || [low isEqualToString:@"true"] || [low isEqualToString:@"yes"] || [low isEqualToString:@"on"]) {
        return YES;
    }
    if ([low isEqualToString:@"0"] || [low isEqualToString:@"false"] || [low isEqualToString:@"no"] || [low isEqualToString:@"off"]) {
        return NO;
    }
    return defaultVal;
}

static NSArray<NSString *> *parseCsvList(NSString *val) {
    if (!val || val.length == 0) return @[];
    NSMutableArray<NSString *> *out = [NSMutableArray array];
    for (NSString *part in [val componentsSeparatedByString:@","]) {
        NSString *clean = [part stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (clean.length > 0) {
            [out addObject:clean];
        }
    }
    return out;
}

static BOOL isValidUUID(NSString *str) {
    if (!str || str.length != 36) return NO;
    static NSRegularExpression *uuidRx = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        uuidRx = [NSRegularExpression regularExpressionWithPattern:@"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
                                                           options:0
                                                             error:nil];
    });
    return [uuidRx numberOfMatchesInString:str options:0 range:NSMakeRange(0, str.length)] == 1;
}

@interface BridgeDaemon : NSObject

@property (nonatomic, strong) NSString *baseDir;
@property (nonatomic, strong) NSString *envPath;
@property (nonatomic, strong) NSDate *lastEnvMtime;

// Identity & routing
@property (nonatomic, strong) NSArray<NSString *> *adminHandles;
@property (nonatomic, strong) NSArray<NSString *> *allowedSenders;
@property (nonatomic, strong) NSSet<NSString *> *normAdmins;
@property (nonatomic, strong) NSSet<NSString *> *normAllowed;
@property (nonatomic, strong) NSSet<NSString *> *allowedServices;
@property (nonatomic, assign) NSTimeInterval maxMessageAgeSeconds;
@property (nonatomic, assign) NSInteger maxRequestsPerMinute;
@property (nonatomic, strong) NSArray<NSString *> *triggerPrefixes;
@property (nonatomic, strong) NSArray<NSString *> *midsentenceKeywords;
@property (nonatomic, assign) BOOL requirePrefix;
@property (nonatomic, strong) NSSet<NSString *> *resetChatCommands;

// Paths & workspaces
@property (nonatomic, strong) NSString *dbPath;
@property (nonatomic, strong) NSString *statePath;
@property (nonatomic, strong) NSString *approvalDir;
@property (nonatomic, strong) NSString *agyBinary;
@property (nonatomic, assign) BOOL disclaimChildTcc;
@property (nonatomic, strong) NSString *defaultConvLabel;
@property (nonatomic, strong) NSString *restrictedWorkspaceDir;
@property (nonatomic, strong) NSString *adminWorkspaceDir;
@property (nonatomic, strong) NSString *restrictedSettingsPath;
@property (nonatomic, strong) NSString *adminSettingsPath;

// Execution, sandboxing & timeouts
@property (nonatomic, strong) NSString *modelRestricted;
@property (nonatomic, strong) NSString *modelAdmin;
@property (nonatomic, assign) BOOL restrictedSandbox;
@property (nonatomic, assign) BOOL adminSandbox;
@property (nonatomic, assign) BOOL disableSlashCommands;
@property (nonatomic, strong) NSString *agyPrintTimeout;
@property (nonatomic, assign) NSTimeInterval agyTaskTimeout;
@property (nonatomic, assign) NSTimeInterval osascriptTimeout;
@property (nonatomic, assign) NSUInteger maxOutputBytes;
@property (nonatomic, assign) NSUInteger maxLogBytes;
@property (nonatomic, assign) NSTimeInterval lastLogCheckTimestamp;

// 1:1 Admin interactive approval & secret policy
@property (nonatomic, strong) NSString *adminAskDestructive;
@property (nonatomic, strong) NSString *adminAskSecrets;
@property (nonatomic, assign) BOOL requireApprovalCode;
@property (nonatomic, assign) NSInteger approvalTimeoutSeconds;
@property (nonatomic, assign) BOOL redactRestricted;
@property (nonatomic, assign) BOOL redactAdminUnlessApproved;
@property (nonatomic, strong) NSString *extraAllowedCommands;
@property (nonatomic, strong) NSString *extraBlockedPaths;
@property (nonatomic, strong) NSString *allowedReadRoots;

// Polling, deduplication & reply formatting
@property (nonatomic, assign) NSTimeInterval pollInterval;
@property (nonatomic, assign) NSTimeInterval duplicateWindowSeconds;
@property (nonatomic, assign) double similarityThreshold;
@property (nonatomic, assign) NSInteger maxReplyLength;
@property (nonatomic, assign) BOOL sendAck;
@property (nonatomic, strong) NSString *ackText;

// Runtime state
@property (nonatomic, assign) int64_t lastRowId;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSString *> *sessions;
@property (nonatomic, strong) NSMutableArray<NSString *> *lastResumeList;
@property (nonatomic, strong) NSMutableArray<NSString *> *recentSentHashes;
@property (nonatomic, strong) NSMutableArray<NSDictionary *> *recentProcessedPrompts;
@property (nonatomic, strong) NSMutableArray<NSNumber *> *consumedRowIds;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSMutableArray<NSDate *> *> *rateTimestamps;
@property (nonatomic, assign) NSTimeInterval lastApprovalReplyTimestamp;
@property (nonatomic, strong) NSString *lastCheckedDbSignature;
@property (nonatomic, assign) int kqFd;
@property (nonatomic, assign) int watchWalFd;
@property (nonatomic, assign) ino_t watchWalIno;
@property (nonatomic, assign) int watchDbFd;
@property (nonatomic, assign) ino_t watchDbIno;
@property (nonatomic, assign) int watchDirFd;
@property (nonatomic, assign) ino_t watchDirIno;
@property (nonatomic, assign) int watchEnvFd;
@property (nonatomic, assign) ino_t watchEnvIno;
@property (nonatomic, assign) int watchBaseDirFd;
@property (nonatomic, assign) ino_t watchBaseDirIno;

@end

@implementation BridgeDaemon

- (instancetype)initWithBaseDir:(NSString *)baseDir {
    self = [super init];
    if (self) {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *expectedEnv = [baseDir stringByAppendingPathComponent:@".env"];
        if (![fm fileExistsAtPath:expectedEnv]) {
            NSString *configDir = [NSHomeDirectory() stringByAppendingPathComponent:@".config/imessage-agy-bridge"];
            NSString *cwd = [fm currentDirectoryPath];
            NSString *legacyDir = [NSHomeDirectory() stringByAppendingPathComponent:@"Code/imessage-agy-bridge"];
            if ([fm fileExistsAtPath:[configDir stringByAppendingPathComponent:@".env"]]) {
                baseDir = configDir;
            } else if ([fm fileExistsAtPath:[cwd stringByAppendingPathComponent:@".env"]]) {
                baseDir = cwd;
            } else if ([fm fileExistsAtPath:[legacyDir stringByAppendingPathComponent:@".env"]]) {
                baseDir = legacyDir;
            } else {
                baseDir = configDir;
            }
        }
        _baseDir = baseDir;
        _envPath = [baseDir stringByAppendingPathComponent:@".env"];
        _sessions = [NSMutableDictionary dictionary];
        _lastResumeList = [NSMutableArray array];
        _recentSentHashes = [NSMutableArray array];
        _recentProcessedPrompts = [NSMutableArray array];
        _consumedRowIds = [NSMutableArray array];
        _rateTimestamps = [NSMutableDictionary dictionary];
        _lastApprovalReplyTimestamp = 0.0;
        _lastLogCheckTimestamp = 0.0;
        _kqFd = kqueue();
        _watchWalFd = -1;
        _watchDbFd = -1;
        _watchDirFd = -1;
        _watchEnvFd = -1;
        _watchBaseDirFd = -1;

        [self reloadEnvIfNeeded:YES];
        [self prepareApprovalDirectory];
        [self maintainLogFilesIfNeeded:YES];
    }
    return self;
}

- (void)dealloc {
    if (_watchWalFd >= 0) close(_watchWalFd);
    if (_watchDbFd >= 0) close(_watchDbFd);
    if (_watchDirFd >= 0) close(_watchDirFd);
    if (_watchEnvFd >= 0) close(_watchEnvFd);
    if (_watchBaseDirFd >= 0) close(_watchBaseDirFd);
    if (_kqFd >= 0) close(_kqFd);
}

- (NSString *)resolvePathValue:(NSString *)val defaultRelative:(NSString *)defRel {
    NSString *raw = (val && val.length > 0) ? val : defRel;
    NSString *expanded = [raw stringByExpandingTildeInPath];
    if ([expanded hasPrefix:@"/"]) {
        return expanded;
    }
    return [self.baseDir stringByAppendingPathComponent:expanded];
}

+ (NSString *)normalizeHandle:(NSString *)handle {
    if (!handle || handle.length == 0) return @"";
    NSString *h = [[handle stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] lowercaseString];
    if (h.length == 0 || [h hasPrefix:@"chat"] || [h containsString:@";+;"]) {
        return @"";
    }
    if ([h containsString:@"@"]) {
        return h;
    }

    NSMutableString *digits = [NSMutableString string];
    for (NSUInteger i = 0; i < h.length; i++) {
        unichar c = [h characterAtIndex:i];
        if (c >= '0' && c <= '9') {
            [digits appendFormat:@"%C", c];
        } else if (c == '+' || c == '-' || c == '(' || c == ')' || c == ' ' || c == '.' || c == '\t' || c == 0x00A0) {
            continue;
        } else {
            // Reject alphanumeric non-email strings such as group chat IDs
            return @"";
        }
    }
    if (digits.length < 7) return @"";
    if (digits.length == 10) return [NSString stringWithFormat:@"+1%@", digits];
    if (digits.length == 11 && [digits hasPrefix:@"1"]) return [NSString stringWithFormat:@"+%@", digits];
    return [h hasPrefix:@"+"] ? [NSString stringWithFormat:@"+%@", digits] : digits;
}

- (BOOL)reloadEnvIfNeeded:(BOOL)force {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDictionary *attrs = [fm attributesOfItemAtPath:self.envPath error:nil];
    NSDate *mtime = attrs[NSFileModificationDate];
    if (!force && mtime && self.lastEnvMtime && [mtime isEqualToDate:self.lastEnvMtime]) {
        return NO;
    }
    self.lastEnvMtime = mtime;

    if ([fm fileExistsAtPath:self.envPath]) {
        chmod([self.envPath fileSystemRepresentation], S_IRUSR | S_IWUSR);
    }

    NSMutableDictionary<NSString *, NSString *> *env = [NSMutableDictionary dictionary];
    NSString *content = [NSString stringWithContentsOfFile:self.envPath encoding:NSUTF8StringEncoding error:nil];
    if (content) {
        NSArray<NSString *> *lines = [content componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
        for (NSString *rawLine in lines) {
            NSString *line = [rawLine stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            if (line.length == 0 || [line hasPrefix:@"#"]) continue;
            NSRange eq = [line rangeOfString:@"="];
            if (eq.location == NSNotFound) continue;

            NSString *key = [[line substringToIndex:eq.location] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            NSString *val = [[line substringFromIndex:eq.location + 1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            if (val.length >= 2 && (([val hasPrefix:@"\""] && [val hasSuffix:@"\""]) || ([val hasPrefix:@"'"] && [val hasSuffix:@"'"]))) {
                val = [val substringWithRange:NSMakeRange(1, val.length - 2)];
            }
            if (key.length > 0) {
                env[key] = val ?: @"";
            }
        }
    } else {
        NSLog(@"[WARNING] .env file not found or unreadable at %@", self.envPath);
    }

    if (force) {
        self.adminHandles = parseCsvList(env[@"ADMIN_HANDLES"]);
        self.allowedSenders = parseCsvList(env[@"ALLOWED_SENDERS"]);

        NSMutableSet<NSString *> *admins = [NSMutableSet set];
        for (NSString *a in self.adminHandles) {
            NSString *n = [BridgeDaemon normalizeHandle:a];
            if (n.length > 0) [admins addObject:n];
        }
        self.normAdmins = admins;

        NSMutableSet<NSString *> *allowed = [NSMutableSet setWithSet:admins];
        for (NSString *s in self.allowedSenders) {
            NSString *n = [BridgeDaemon normalizeHandle:s];
            if (n.length > 0) [allowed addObject:n];
        }
        self.normAllowed = allowed;

        NSMutableSet<NSString *> *services = [NSMutableSet set];
        for (NSString *svc in parseCsvList(env[@"ALLOWED_SERVICES"] ?: @"iMessage")) {
            [services addObject:svc.lowercaseString];
        }
        if (services.count == 0) [services addObject:@"imessage"];
        self.allowedServices = services;

        NSString *defaultAgy = [NSHomeDirectory() stringByAppendingPathComponent:@".local/bin/agy"];
        self.dbPath = [[env[@"DB_PATH"] length] > 0 ? env[@"DB_PATH"] : @"~/Library/Messages/chat.db" stringByExpandingTildeInPath];
        self.statePath = [self resolvePathValue:env[@"STATE_FILE"] defaultRelative:@"bridge_state.json"];
        self.approvalDir = [self resolvePathValue:env[@"APPROVAL_DIR"] defaultRelative:@"approvals"];
        self.agyBinary = [[env[@"AGY_BINARY"] length] > 0 ? env[@"AGY_BINARY"] : defaultAgy stringByExpandingTildeInPath];
        self.disclaimChildTcc = parseBoolValue(env[@"DISCLAIM_CHILD_TCC"], YES);
        self.defaultConvLabel = [env[@"CONVERSATION_ID"] length] > 0 ? env[@"CONVERSATION_ID"] : @"imessage-agy-main";

        self.restrictedWorkspaceDir = [[env[@"RESTRICTED_WORKSPACE_DIR"] length] > 0 ? env[@"RESTRICTED_WORKSPACE_DIR"] : @"~/.config/imessage-agy-bridge/workspaces/jail" stringByExpandingTildeInPath];
        self.adminWorkspaceDir = [[env[@"ADMIN_WORKSPACE_DIR"] length] > 0 ? env[@"ADMIN_WORKSPACE_DIR"] : @"~/.config/imessage-agy-bridge/workspaces/admin" stringByExpandingTildeInPath];
        self.restrictedSettingsPath = [self resolvePathValue:env[@"RESTRICTED_SETTINGS_FILE"] defaultRelative:@"workspaces/jail/bridge-settings.json"];
        self.adminSettingsPath = [self resolvePathValue:env[@"ADMIN_SETTINGS_FILE"] defaultRelative:@"workspaces/admin/bridge-settings-admin.json"];

        struct stat st;
        if (stat([self.agyBinary fileSystemRepresentation], &st) == 0) {
            if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0 || (st.st_uid != getuid() && st.st_uid != 0)) {
                NSLog(@"[WARNING] AGY binary %@ has unexpected ownership or write permissions; resetting to %@", self.agyBinary, defaultAgy);
                self.agyBinary = defaultAgy;
            }
        }
    }

    double maxAge = [env[@"MAX_MESSAGE_AGE_SECONDS"] doubleValue];
    self.maxMessageAgeSeconds = (maxAge >= 30.0) ? maxAge : 300.0;

    NSInteger maxRpm = [env[@"MAX_REQUESTS_PER_MINUTE"] integerValue];
    self.maxRequestsPerMinute = (maxRpm >= 1 && maxRpm <= 120) ? maxRpm : 10;

    NSArray<NSString *> *rawPrefixes = parseCsvList(env[@"TRIGGER_PREFIXES"] ?: @"@agy,!agy");
    self.triggerPrefixes = [rawPrefixes sortedArrayUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
        if (a.length > b.length) return NSOrderedAscending;
        if (a.length < b.length) return NSOrderedDescending;
        return NSOrderedSame;
    }];

    self.midsentenceKeywords = parseCsvList(env[@"MIDSENTENCE_KEYWORDS"] ?: @"@agy");
    self.requirePrefix = parseBoolValue(env[@"REQUIRE_PREFIX"], YES);

    NSMutableSet<NSString *> *newCmds = [NSMutableSet set];
    for (NSString *c in parseCsvList(env[@"NEW_CHAT_COMMANDS"] ?: @"/new,/clear,/reset")) {
        [newCmds addObject:c.lowercaseString];
    }
    self.resetChatCommands = newCmds;

    self.modelRestricted = [env[@"AGY_MODEL_RESTRICTED"] ?: @"" stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    self.modelAdmin = [env[@"AGY_MODEL_ADMIN"] ?: @"" stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    self.restrictedSandbox = parseBoolValue(env[@"RESTRICTED_SANDBOX"], YES);
    self.adminSandbox = parseBoolValue(env[@"ADMIN_SANDBOX"], NO);
    self.disableSlashCommands = parseBoolValue(env[@"DISABLE_SLASH_COMMANDS"], YES);
    self.agyPrintTimeout = [env[@"AGY_PRINT_TIMEOUT"] length] > 0 ? env[@"AGY_PRINT_TIMEOUT"] : @"90s";

    double taskTo = [env[@"AGY_TASK_TIMEOUT_SECONDS"] doubleValue];
    self.agyTaskTimeout = (taskTo >= 20.0) ? taskTo : 110.0;

    double osaTo = [env[@"OSASCRIPT_TIMEOUT_SECONDS"] doubleValue];
    self.osascriptTimeout = (osaTo >= 5.0) ? osaTo : 15.0;

    NSInteger maxBytes = [env[@"MAX_OUTPUT_BYTES"] integerValue];
    self.maxOutputBytes = (maxBytes >= 16384) ? (NSUInteger)maxBytes : 262144;

    NSInteger maxLog = [env[@"MAX_LOG_BYTES"] integerValue];
    self.maxLogBytes = (maxLog >= 262144) ? (NSUInteger)maxLog : 5242880;

    BOOL askDestr = parseBoolValue(env[@"ADMIN_ASK_FOR_DESTRUCTIVE"], YES);
    BOOL askSec = parseBoolValue(env[@"ADMIN_ASK_FOR_SECRETS"], YES);
    self.adminAskDestructive = askDestr ? @"true" : @"false";
    self.adminAskSecrets = askSec ? @"true" : @"false";
    self.requireApprovalCode = parseBoolValue(env[@"REQUIRE_APPROVAL_CODE"], YES);

    NSInteger appTo = [env[@"APPROVAL_TIMEOUT_SECONDS"] integerValue];
    self.approvalTimeoutSeconds = (appTo >= 15 && appTo <= 300) ? appTo : 90;

    self.redactRestricted = parseBoolValue(env[@"REDACT_SECRETS_RESTRICTED"], YES);
    self.redactAdminUnlessApproved = parseBoolValue(env[@"REDACT_SECRETS_ADMIN_UNLESS_APPROVED"], YES);

    self.extraAllowedCommands = env[@"EXTRA_ALLOWED_COMMANDS"] ?: @"";
    self.extraBlockedPaths = env[@"EXTRA_BLOCKED_PATHS"] ?: @"";
    self.allowedReadRoots = env[@"ALLOWED_READ_ROOTS"] ?: @"";

    double poll = [env[@"POLL_INTERVAL_SECONDS"] doubleValue];
    self.pollInterval = (poll > 0.0) ? MAX(poll, 0.5) : 0.0;

    double dupWin = [env[@"DUPLICATE_WINDOW_SECONDS"] doubleValue];
    self.duplicateWindowSeconds = (dupWin >= 5.0) ? dupWin : 90.0;

    double sim = [env[@"SIMILARITY_THRESHOLD"] doubleValue];
    self.similarityThreshold = (sim >= 0.5 && sim <= 1.0) ? sim : 0.80;

    NSInteger maxLen = [env[@"MAX_REPLY_LENGTH"] integerValue];
    self.maxReplyLength = (maxLen >= 300) ? maxLen : 1800;

    self.sendAck = parseBoolValue(env[@"SEND_ACK"], YES);
    self.ackText = [env[@"ACK_TEXT"] length] > 0 ? env[@"ACK_TEXT"] : @"🤖 AGY is thinking...";

    NSLog(@"[CONFIG] Loaded .env (admins=%lu, whitelisted=%lu, poll=%0.1fs, adminAskDestructive=%@, adminAskSecrets=%@)",
          (unsigned long)self.normAdmins.count,
          (unsigned long)self.normAllowed.count,
          self.pollInterval,
          self.adminAskDestructive,
          self.adminAskSecrets);
    return YES;
}

- (void)prepareApprovalDirectory {
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm createDirectoryAtPath:self.approvalDir withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions: @(0700)} error:nil];
    chmod([self.approvalDir fileSystemRepresentation], S_IRWXU);
    NSArray<NSString *> *files = [fm contentsOfDirectoryAtPath:self.approvalDir error:nil];
    for (NSString *fn in files) {
        if ([fn hasSuffix:@".json"] || [fn hasSuffix:@".tmp"]) {
            [fm removeItemAtPath:[self.approvalDir stringByAppendingPathComponent:fn] error:nil];
        }
    }
}

- (void)maintainLogFilesIfNeeded:(BOOL)force {
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (!force && (now - self.lastLogCheckTimestamp) < 60.0) {
        return;
    }
    self.lastLogCheckTimestamp = now;

    NSUInteger limitBytes = (self.maxLogBytes >= 262144) ? self.maxLogBytes : 5242880;
    NSUInteger keepBytes = limitBytes / 2;

    for (NSString *logName in @[@"bridge.err.log", @"bridge.log"]) {
        NSString *logPath = [self.baseDir stringByAppendingPathComponent:logName];
        const char *cPath = [logPath fileSystemRepresentation];
        struct stat st;
        if (stat(cPath, &st) != 0) continue;

        if ((st.st_mode & 0777) != (S_IRUSR | S_IWUSR)) {
            chmod(cPath, S_IRUSR | S_IWUSR);
        }

        if ((NSUInteger)st.st_size > limitBytes) {
            int rfd = open(cPath, O_RDONLY);
            if (rfd >= 0) {
                off_t offset = st.st_size > (off_t)keepBytes ? (st.st_size - (off_t)keepBytes) : 0;
                lseek(rfd, offset, SEEK_SET);
                NSMutableData *tail = [NSMutableData dataWithLength:keepBytes];
                ssize_t nread = read(rfd, tail.mutableBytes, keepBytes);
                close(rfd);

                if (nread > 0) {
                    [tail setLength:(NSUInteger)nread];
                    const uint8_t *bytes = (const uint8_t *)tail.bytes;
                    NSUInteger startIdx = 0;
                    for (NSUInteger i = 0; i < (NSUInteger)nread; i++) {
                        if (bytes[i] == '\n') {
                            startIdx = i + 1;
                            break;
                        }
                    }
                    NSData *trimmed = (startIdx < (NSUInteger)nread)
                        ? [tail subdataWithRange:NSMakeRange(startIdx, (NSUInteger)nread - startIdx)]
                        : tail;

                    int wfd = open(cPath, O_WRONLY | O_TRUNC);
                    if (wfd >= 0) {
                        fchmod(wfd, S_IRUSR | S_IWUSR);
                        (void)write(wfd, trimmed.bytes, trimmed.length);
                        close(wfd);
                        NSLog(@"[LOG] Trimmed %@ in-place from %lld bytes to %lu bytes (max=%lu)",
                              logName, (long long)st.st_size, (unsigned long)trimmed.length, (unsigned long)limitBytes);
                    }
                }
            }
        }
    }
}

- (NSString *)currentDbStateSignature {
    struct stat stDb, stWal;
    memset(&stDb, 0, sizeof(stDb));
    memset(&stWal, 0, sizeof(stWal));
    const char *dbC = [self.dbPath fileSystemRepresentation];
    const char *walC = [[self.dbPath stringByAppendingString:@"-wal"] fileSystemRepresentation];
    int rcDb = stat(dbC, &stDb);
    int rcWal = stat(walC, &stWal);
    return [NSString stringWithFormat:@"%d:%llu:%lld:%ld.%ld|%d:%llu:%lld:%ld.%ld",
            rcDb,
            (unsigned long long)stDb.st_ino,
            (long long)stDb.st_size,
            (long)stDb.st_mtimespec.tv_sec,
            (long)stDb.st_mtimespec.tv_nsec,
            rcWal,
            (unsigned long long)stWal.st_ino,
            (long long)stWal.st_size,
            (long)stWal.st_mtimespec.tv_sec,
            (long)stWal.st_mtimespec.tv_nsec];
}

- (void)refreshKqueueWatchForPath:(NSString *)path fdPtr:(int *)fdPtr inoPtr:(ino_t *)inoPtr {
    if (!path || path.length == 0 || self.kqFd < 0) return;
    struct stat st;
    if (stat([path fileSystemRepresentation], &st) != 0) {
        if (*fdPtr >= 0) {
            close(*fdPtr);
            *fdPtr = -1;
            *inoPtr = 0;
        }
        return;
    }
    if (*fdPtr >= 0 && *inoPtr == st.st_ino) {
        return;
    }
    if (*fdPtr >= 0) {
        close(*fdPtr);
        *fdPtr = -1;
        *inoPtr = 0;
    }
    int fd = open([path fileSystemRepresentation], O_EVTONLY | O_CLOEXEC);
    if (fd >= 0) {
        struct kevent ev;
        EV_SET(&ev,
               fd,
               EVFILT_VNODE,
               EV_ADD | EV_CLEAR,
               NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE,
               0,
               NULL);
        if (kevent(self.kqFd, &ev, 1, NULL, 0, NULL) == 0) {
            *fdPtr = fd;
            *inoPtr = st.st_ino;
        } else {
            close(fd);
        }
    }
}

- (BOOL)waitForDatabaseOrEnvChangeWithTimeout:(NSTimeInterval)timeoutSec {
    NSString *sigBefore = [self currentDbStateSignature];
    if (!self.lastCheckedDbSignature || ![sigBefore isEqualToString:self.lastCheckedDbSignature]) {
        return YES;
    }

    if (self.kqFd < 0) {
        [NSThread sleepForTimeInterval:MIN(MAX(timeoutSec, 0.25), 5.0)];
        return ![[self currentDbStateSignature] isEqualToString:self.lastCheckedDbSignature];
    }

    NSString *walPath = [self.dbPath stringByAppendingString:@"-wal"];
    NSString *dirPath = [self.dbPath stringByDeletingLastPathComponent];
    [self refreshKqueueWatchForPath:walPath fdPtr:&_watchWalFd inoPtr:&_watchWalIno];
    [self refreshKqueueWatchForPath:self.dbPath fdPtr:&_watchDbFd inoPtr:&_watchDbIno];
    [self refreshKqueueWatchForPath:dirPath fdPtr:&_watchDirFd inoPtr:&_watchDirIno];
    [self refreshKqueueWatchForPath:self.envPath fdPtr:&_watchEnvFd inoPtr:&_watchEnvIno];
    [self refreshKqueueWatchForPath:self.baseDir fdPtr:&_watchBaseDirFd inoPtr:&_watchBaseDirIno];

    NSString *sigAfterReg = [self currentDbStateSignature];
    if (![sigAfterReg isEqualToString:self.lastCheckedDbSignature]) {
        return YES;
    }

    struct timespec ts;
    struct timespec *tsPtr = NULL;
    if (timeoutSec > 0.0) {
        ts.tv_sec = (time_t)timeoutSec;
        ts.tv_nsec = (long)((timeoutSec - (double)ts.tv_sec) * 1e9);
        tsPtr = &ts;
    }

    struct kevent events[8];
    int nev = kevent(self.kqFd, NULL, 0, events, 8, tsPtr);
    if (nev > 0) {
        for (int i = 0; i < nev; i++) {
            if (events[i].fflags & (NOTE_DELETE | NOTE_RENAME | NOTE_REVOKE)) {
                int evFd = (int)events[i].ident;
                if (evFd == _watchWalFd) { close(_watchWalFd); _watchWalFd = -1; _watchWalIno = 0; }
                else if (evFd == _watchDbFd) { close(_watchDbFd); _watchDbFd = -1; _watchDbIno = 0; }
                else if (evFd == _watchDirFd) { close(_watchDirFd); _watchDirFd = -1; _watchDirIno = 0; }
                else if (evFd == _watchEnvFd) { close(_watchEnvFd); _watchEnvFd = -1; _watchEnvIno = 0; }
                else if (evFd == _watchBaseDirFd) { close(_watchBaseDirFd); _watchBaseDirFd = -1; _watchBaseDirIno = 0; }
            }
        }
        // Coalesce rapid SQLite WAL writes (message + chat_message_join) before opening SQLite
        [NSThread sleepForTimeInterval:0.06];
    }

    return ![[self currentDbStateSignature] isEqualToString:self.lastCheckedDbSignature];
}

- (BOOL)isWhitelisted:(NSString *)handle {
    NSString *norm = [BridgeDaemon normalizeHandle:handle];
    return (norm.length > 0 && [self.normAllowed containsObject:norm]);
}

- (BOOL)isPrimaryAdmin:(NSString *)handle {
    NSString *norm = [BridgeDaemon normalizeHandle:handle];
    return (norm.length > 0 && [self.normAdmins containsObject:norm]);
}

- (NSString *)primaryAdminDefaultHandle {
    for (NSString *h in self.adminHandles) {
        if ([BridgeDaemon normalizeHandle:h].length > 0) {
            return h;
        }
    }
    return @"";
}

- (void)recordConsumedRowId:(int64_t)rowId {
    [self.consumedRowIds addObject:@(rowId)];
    if (self.consumedRowIds.count > 500) {
        [self.consumedRowIds removeObjectAtIndex:0];
    }
}

- (NSString *)redactPrivateKeys:(NSString *)text {
    if (!text || text.length == 0) return @"";
    NSMutableString *result = [NSMutableString stringWithString:text];
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"-----BEGIN [A-Za-z0-9 ]+PRIVATE KEY-----[\\s\\S]*?-----END [A-Za-z0-9 ]+PRIVATE KEY-----" options:0 error:nil];
    if (regex) {
        [regex replaceMatchesInString:result options:0 range:NSMakeRange(0, result.length) withTemplate:@"[REDACTED_PRIVATE_KEY]"];
    }
    return result;
}

- (NSString *)redactSecrets:(NSString *)text {
    if (!text || text.length == 0) return @"";
    NSMutableString *result = [NSMutableString stringWithString:[self redactPrivateKeys:text]];

    NSArray<NSString *> *patterns = @[
        @"ssh-(?:ed25519|rsa|dss|ecdsa)\\s+[A-Za-z0-9+/=]{30,}",
        @"ecdsa-sha2-[a-z0-9-]+\\s+[A-Za-z0-9+/=]{30,}",
        @"(?i)(?:api[_-]?key|password|passwd|token|secret|auth[_-]?token|bearer|client[_-]?secret)\\s*[:=]+\\s*['\"]?[A-Za-z0-9_\\-\\.~\\+/=]{8,}['\"]?",
        @"AIza[0-9A-Za-z\\-_]{35}",
        @"ya29\\.[0-9A-Za-z\\-_]{25,}",
        @"gh[pousr]_[0-9A-Za-z]{30,}",
        @"github_pat_[0-9A-Za-z_]{40,}",
        @"glpat-[0-9A-Za-z\\-_]{20,}",
        @"xox[baprs]-[0-9A-Za-z\\-_]{10,}",
        @"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        @"sk-[A-Za-z0-9\\-_]{24,}",
        @"eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"
    ];

    for (NSString *pat in patterns) {
        NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:pat options:0 error:nil];
        if (regex) {
            [regex replaceMatchesInString:result options:0 range:NSMakeRange(0, result.length) withTemplate:@"[REDACTED_SECRET]"];
        }
    }
    return result;
}

- (BOOL)checkRateLimitForContext:(NSString *)contextKey {
    if (self.maxRequestsPerMinute <= 0 || !contextKey) return YES;
    NSDate *now = [NSDate date];
    NSMutableArray<NSDate *> *history = self.rateTimestamps[contextKey];
    if (!history) {
        history = [NSMutableArray array];
        self.rateTimestamps[contextKey] = history;
    }
    NSMutableArray<NSDate *> *recent = [NSMutableArray array];
    for (NSDate *ts in history) {
        if ([now timeIntervalSinceDate:ts] < 60.0) {
            [recent addObject:ts];
        }
    }
    if ((NSInteger)recent.count >= self.maxRequestsPerMinute) {
        self.rateTimestamps[contextKey] = recent;
        return NO;
    }
    [recent addObject:now];
    self.rateTimestamps[contextKey] = recent;
    return YES;
}

- (NSSet<NSString *> *)extractKeywords:(NSString *)str {
    NSMutableString *clean = [NSMutableString string];
    NSString *lower = str.lowercaseString;
    for (NSUInteger i = 0; i < lower.length; i++) {
        unichar c = [lower characterAtIndex:i];
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ' ') {
            [clean appendFormat:@"%C", c];
        } else {
            [clean appendString:@" "];
        }
    }

    static NSSet<NSString *> *stopWords = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        stopWords = [NSSet setWithObjects:
            @"is", @"the", @"a", @"an", @"on", @"this", @"that", @"up", @"running",
            @"what", @"how", @"are", @"in", @"of", @"to", @"for", @"it", @"me",
            @"please", @"can", @"you", @"tell", @"give", @"show", @"now", @"repeat", nil];
    });

    NSMutableSet<NSString *> *keywords = [NSMutableSet set];
    for (NSString *w in [clean componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]]) {
        if (w.length > 1 && ![stopWords containsObject:w]) {
            [keywords addObject:w];
        }
    }
    return keywords;
}

- (BOOL)isPromptSimilar:(NSString *)p1 toRecent:(NSString *)p2 {
    NSString *s1 = [[p1 stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] lowercaseString];
    NSString *s2 = [[p2 stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] lowercaseString];
    if ([s1 isEqualToString:s2]) return YES;

    NSSet<NSString *> *k1 = [self extractKeywords:s1];
    NSSet<NSString *> *k2 = [self extractKeywords:s2];
    if (k1.count == 0 || k2.count == 0) {
        return [s1 isEqualToString:s2];
    }

    NSMutableSet<NSString *> *inter = [NSMutableSet setWithSet:k1];
    [inter intersectSet:k2];

    NSMutableSet<NSString *> *uni = [NSMutableSet setWithSet:k1];
    [uni unionSet:k2];

    if (uni.count == 0) return NO;
    double jaccard = (double)inter.count / (double)uni.count;
    return (jaccard >= self.similarityThreshold);
}

- (BOOL)isBuiltinCommand:(NSString *)prompt {
    NSString *trimmed = [prompt stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (trimmed.length == 0) return NO;
    NSArray<NSString *> *parts = [trimmed componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    NSString *first = parts.firstObject.lowercaseString ?: @"";
    if ([self.resetChatCommands containsObject:first]) return YES;
    return ([first isEqualToString:@"/resume"] ||
            [first isEqualToString:@"/status"] ||
            [first isEqualToString:@"/session"] ||
            [first isEqualToString:@"/reload"] ||
            [first isEqualToString:@"/help"]);
}

- (BOOL)isDuplicatePrompt:(NSString *)prompt forContext:(NSString *)contextKey {
    NSDate *now = [NSDate date];
    BOOL isCmd = [self isBuiltinCommand:prompt];
    NSMutableArray<NSDictionary *> *valid = [NSMutableArray array];
    BOOL isDup = NO;
    NSString *matched = nil;

    for (NSDictionary *entry in self.recentProcessedPrompts) {
        NSDate *ts = entry[@"timestamp"];
        BOOL entryIsCmd = [entry[@"is_cmd"] boolValue];
        NSTimeInterval window = entryIsCmd ? 5.0 : self.duplicateWindowSeconds;
        if ([now timeIntervalSinceDate:ts] <= window) {
            [valid addObject:entry];
            if (!isDup && [entry[@"context"] isEqualToString:contextKey]) {
                NSString *oldPrompt = entry[@"prompt"];
                if (isCmd) {
                    if ([prompt.lowercaseString isEqualToString:oldPrompt.lowercaseString]) {
                        isDup = YES;
                        matched = oldPrompt;
                    }
                } else if (!entryIsCmd && [self isPromptSimilar:prompt toRecent:oldPrompt]) {
                    isDup = YES;
                    matched = oldPrompt;
                }
            }
        }
    }
    self.recentProcessedPrompts = valid;
    if (isDup) {
        NSLog(@"[INFO] Skipping duplicate in '%@': '%@' (matched '%@')", contextKey, prompt, matched);
    }
    return isDup;
}

- (void)recordProcessedPrompt:(NSString *)prompt forContext:(NSString *)contextKey {
    [self.recentProcessedPrompts addObject:@{
        @"prompt": prompt ?: @"",
        @"context": contextKey ?: @"",
        @"timestamp": [NSDate date],
        @"is_cmd": @([self isBuiltinCommand:prompt])
    }];
}

- (NSString *)hashString:(NSString *)str {
    NSString *trimmed = [str stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    const char *ptr = [trimmed UTF8String];
    if (!ptr) return @"";
    unsigned char md[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(ptr, (CC_LONG)strlen(ptr), md);
    NSMutableString *res = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [res appendFormat:@"%02x", md[i]];
    }
    return res;
}

- (void)recordSentHash:(NSString *)text {
    NSString *h = [self hashString:text];
    if (h.length == 0) return;
    [self.recentSentHashes addObject:h];
    if (self.recentSentHashes.count > 300) {
        [self.recentSentHashes removeObjectAtIndex:0];
    }
}

- (BOOL)isSelfEcho:(NSString *)text {
    NSString *s = [text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if ([s hasPrefix:@"🤖 "] || [s hasPrefix:@"🔐 "] || [s hasPrefix:@"✅ "] || [s hasPrefix:@"🛑 "]) {
        return YES;
    }
    return [self.recentSentHashes containsObject:[self hashString:s]];
}

- (NSString *)cleanExtractedString:(NSString *)str {
    if (!str || str.length == 0) return @"";
    NSString *cleaned = [str stringByReplacingOccurrencesOfString:@"\uFFFC" withString:@""];
    cleaned = [cleaned stringByReplacingOccurrencesOfString:@"\uFEFF" withString:@""];
    return [cleaned stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

- (NSString *)extractTextFromRow:(const char *)rawText bodyData:(const void *)bodyBytes length:(int)bodyLen {
    if (rawText && strlen(rawText) > 0) {
        NSString *s = [NSString stringWithUTF8String:rawText];
        if (s && s.length > 0) return [self cleanExtractedString:s];
    }
    if (!bodyBytes || bodyLen <= 0) return @"";

    NSData *data = [NSData dataWithBytes:bodyBytes length:(NSUInteger)bodyLen];

    @try {
        NSSet *classes = [NSSet setWithObjects:[NSAttributedString class], [NSString class], [NSDictionary class], [NSArray class], nil];
        NSAttributedString *attrStr = [NSKeyedUnarchiver unarchivedObjectOfClasses:classes fromData:data error:nil];
        if (attrStr && attrStr.string.length > 0) {
            return [self cleanExtractedString:attrStr.string];
        }
    } @catch (NSException *e) {}

    // Decode Apple legacy typedstream ("NSString" ... 0x2B <1-byte | 0x81 uint16-LE | 0x82 uint32-LE> <utf8_bytes>)
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    const char marker[] = "NSString";
    const size_t markerLen = strlen(marker);
    const void *found = memmem(bytes, (size_t)bodyLen, marker, markerLen);
    if (found) {
        const uint8_t *after = (const uint8_t *)found + markerLen;
        int64_t remaining = (int64_t)(bytes + bodyLen - after);
        for (int64_t i = 0; i < remaining - 2; i++) {
            if (after[i] != 0x2B) continue;

            uint8_t lenTag = after[i + 1];
            uint64_t strLen = 0;
            int64_t payloadOffset = 0;

            if (lenTag < 0x80) {
                strLen = lenTag;
                payloadOffset = i + 2;
            } else if (lenTag == 0x81 && i + 4 <= remaining) {
                strLen = (uint64_t)after[i + 2] | ((uint64_t)after[i + 3] << 8);
                payloadOffset = i + 4;
            } else if (lenTag == 0x82 && i + 6 <= remaining) {
                strLen = (uint64_t)after[i + 2]
                       | ((uint64_t)after[i + 3] << 8)
                       | ((uint64_t)after[i + 4] << 16)
                       | ((uint64_t)after[i + 5] << 24);
                payloadOffset = i + 6;
            } else {
                continue;
            }

            if (strLen > 0 && strLen <= 1048576 && payloadOffset + (int64_t)strLen <= remaining) {
                NSData *sub = [NSData dataWithBytes:after + payloadOffset length:(NSUInteger)strLen];
                NSString *s = [[NSString alloc] initWithData:sub encoding:NSUTF8StringEncoding];
                if (s && s.length > 0) {
                    return [self cleanExtractedString:s];
                }
            }
        }
    }
    return @"";
}

- (int64_t)queryMaxRowId {
    sqlite3 *db = NULL;
    NSString *uri = [NSString stringWithFormat:@"file:%@?mode=ro", self.dbPath];
    int64_t maxId = 0;
    if (sqlite3_open_v2([uri UTF8String], &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) == SQLITE_OK) {
        sqlite3_busy_timeout(db, 2000);
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, "SELECT COALESCE(MAX(ROWID), 0) FROM message;", -1, &stmt, NULL) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                maxId = sqlite3_column_int64(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    } else if (db) {
        sqlite3_close(db);
    }
    return maxId;
}

- (NSArray<NSDictionary *> *)fetchMessagesSinceRowId:(int64_t)sinceRowId limit:(int)limit {
    NSMutableArray<NSDictionary *> *rows = [NSMutableArray array];
    sqlite3 *db = NULL;
    NSString *uri = [NSString stringWithFormat:@"file:%@?mode=ro", self.dbPath];
    if (sqlite3_open_v2([uri UTF8String], &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return rows;
    }
    sqlite3_busy_timeout(db, 2000);

    const char *sql =
        "SELECT "
        "  m.ROWID, "
        "  m.text, "
        "  m.attributedBody, "
        "  m.is_from_me, "
        "  COALESCE(h.id, ''), "
        "  COALESCE(c.chat_identifier, ''), "
        "  COALESCE(c.guid, ''), "
        "  COALESCE(c.style, 0), "
        "  COALESCE(m.service, ''), "
        "  COALESCE(m.date, 0) "
        "FROM message m "
        "LEFT JOIN handle h ON m.handle_id = h.ROWID "
        "LEFT JOIN chat_message_join cmj ON m.ROWID = cmj.message_id "
        "LEFT JOIN chat c ON cmj.chat_id = c.ROWID "
        "WHERE m.ROWID > ? "
        "ORDER BY m.ROWID ASC "
        "LIMIT ?;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, sinceRowId);
        sqlite3_bind_int(stmt, 2, limit > 0 ? limit : 200);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int64_t rowId = sqlite3_column_int64(stmt, 0);
            const char *rawText = (const char *)sqlite3_column_text(stmt, 1);
            const void *bodyBytes = sqlite3_column_blob(stmt, 2);
            int bodyLen = sqlite3_column_bytes(stmt, 2);
            int isFromMe = sqlite3_column_int(stmt, 3);
            const char *rawHandle = (const char *)sqlite3_column_text(stmt, 4);
            const char *rawChatId = (const char *)sqlite3_column_text(stmt, 5);
            const char *rawGuid = (const char *)sqlite3_column_text(stmt, 6);
            int chatStyle = sqlite3_column_int(stmt, 7);
            const char *rawService = (const char *)sqlite3_column_text(stmt, 8);
            int64_t msgDate = sqlite3_column_int64(stmt, 9);

            NSString *text = [self extractTextFromRow:rawText bodyData:bodyBytes length:bodyLen] ?: @"";
            NSString *handleId = rawHandle ? ([NSString stringWithUTF8String:rawHandle] ?: @"") : @"";
            NSString *chatIdentifier = rawChatId ? ([NSString stringWithUTF8String:rawChatId] ?: @"") : @"";
            NSString *chatGuid = rawGuid ? ([NSString stringWithUTF8String:rawGuid] ?: @"") : @"";
            NSString *service = rawService ? ([NSString stringWithUTF8String:rawService] ?: @"") : @"";

            [rows addObject:@{
                @"rowid": @(rowId),
                @"text": text,
                @"is_from_me": @(isFromMe),
                @"handle_id": handleId,
                @"chat_identifier": chatIdentifier,
                @"chat_guid": chatGuid,
                @"chat_style": @(chatStyle),
                @"service": service,
                @"date": @(msgDate)
            }];
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return rows;
}

- (void)loadState {
    if ([[NSFileManager defaultManager] fileExistsAtPath:self.statePath]) {
        NSData *data = [NSData dataWithContentsOfFile:self.statePath];
        if (data) {
            NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if ([dict isKindOfClass:[NSDictionary class]] && dict[@"last_rowid"]) {
                self.lastRowId = [dict[@"last_rowid"] longLongValue];
                NSDictionary *rawSess = dict[@"sessions"];
                if ([rawSess isKindOfClass:[NSDictionary class]]) {
                    for (id k in rawSess) {
                        id v = rawSess[k];
                        if ([k isKindOfClass:[NSString class]] && [v isKindOfClass:[NSString class]] && isValidUUID(v)) {
                            self.sessions[k] = v;
                        }
                    }
                }
                NSArray *rawRes = dict[@"last_resume_list"];
                if ([rawRes isKindOfClass:[NSArray class]]) {
                    for (id item in rawRes) {
                        if ([item isKindOfClass:[NSString class]] && isValidUUID(item)) {
                            [self.lastResumeList addObject:item];
                        }
                    }
                }
                NSLog(@"[STATE] Loaded state (last_rowid=%lld, active_sessions=%lu)", self.lastRowId, (unsigned long)self.sessions.count);
                return;
            }
        }
    }
    self.lastRowId = [self queryMaxRowId];
    NSLog(@"[STATE] Initialized state starting at message ROWID %lld", self.lastRowId);
    [self saveState];
}

- (void)saveState {
    NSArray<NSString *> *cappedResume = self.lastResumeList.count > 15
        ? [self.lastResumeList subarrayWithRange:NSMakeRange(0, 15)]
        : self.lastResumeList;

    NSDictionary *dict = @{
        @"last_rowid": @(self.lastRowId),
        @"sessions": self.sessions ?: @{},
        @"last_resume_list": cappedResume ?: @[],
        @"updated_at": @([[NSDate date] timeIntervalSince1970])
    };
    NSData *data = [NSJSONSerialization dataWithJSONObject:dict options:NSJSONWritingPrettyPrinted error:nil];
    if (data) {
        [data writeToFile:self.statePath atomically:YES];
        chmod([self.statePath fileSystemRepresentation], S_IRUSR | S_IWUSR);
    }
}

- (void)drainFileHandle:(NSFileHandle *)fh intoData:(NSMutableData *)sink maxBytes:(NSUInteger)maxBytes {
    int fd = [fh fileDescriptor];
    uint8_t buf[8192];
    while (true) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        if (sink.length < maxBytes) {
            NSUInteger room = maxBytes - sink.length;
            NSUInteger take = ((NSUInteger)n < room) ? (NSUInteger)n : room;
            [sink appendBytes:buf length:take];
        }
    }
}

- (BOOL)sendIMessageTo:(NSString *)recipient text:(NSString *)text isGroup:(BOOL)isGroup chatGuid:(NSString *)chatGuid {
    [self recordSentHash:text];

    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:@"/usr/bin/osascript"];

    if (isGroup && chatGuid.length > 0) {
        NSString *script =
            @"on run argv\n"
            @"  tell application \"Messages\"\n"
            @"    set targetChat to 1st chat whose id = (item 1 of argv)\n"
            @"    send (item 2 of argv) to targetChat\n"
            @"  end tell\n"
            @"end run";
        task.arguments = @[@"-e", script, chatGuid, text];
    } else {
        NSString *script =
            @"on run argv\n"
            @"  tell application \"Messages\"\n"
            @"    set targetService to 1st account whose service type = iMessage\n"
            @"    set targetBuddy to participant (item 1 of argv) of targetService\n"
            @"    send (item 2 of argv) to targetBuddy\n"
            @"  end tell\n"
            @"end run";
        task.arguments = @[@"-e", script, recipient, text];
    }

    NSPipe *outPipe = [NSPipe pipe];
    NSPipe *errPipe = [NSPipe pipe];
    task.standardOutput = outPipe;
    task.standardError = errPipe;

    NSError *launchErr = nil;
    if (![task launchAndReturnError:&launchErr]) {
        NSLog(@"[ERROR] Failed to launch osascript: %@", launchErr);
        return NO;
    }
    [[outPipe fileHandleForWriting] closeFile];
    [[errPipe fileHandleForWriting] closeFile];

    NSMutableData *errData = [NSMutableData data];
    dispatch_group_t grp = dispatch_group_create();
    dispatch_group_async(grp, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSMutableData *dummy = [NSMutableData data];
        [self drainFileHandle:[outPipe fileHandleForReading] intoData:dummy maxBytes:4096];
        [[outPipe fileHandleForReading] closeFile];
    });
    dispatch_group_async(grp, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        [self drainFileHandle:[errPipe fileHandleForReading] intoData:errData maxBytes:16384];
        [[errPipe fileHandleForReading] closeFile];
    });

    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:self.osascriptTimeout];
    while (task.isRunning) {
        if ([[NSDate date] compare:deadline] == NSOrderedDescending) {
            NSLog(@"[ERROR] osascript timed out after %0.1fs; killing PID %d", self.osascriptTimeout, task.processIdentifier);
            [task terminate];
            [NSThread sleepForTimeInterval:0.5];
            if (task.isRunning) kill(task.processIdentifier, SIGKILL);
            break;
        }
        [NSThread sleepForTimeInterval:0.1];
    }
    [task waitUntilExit];
    dispatch_group_wait(grp, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)));

    if (task.terminationStatus != 0) {
        NSString *errStr = [[NSString alloc] initWithData:errData encoding:NSUTF8StringEncoding] ?: @"";
        NSLog(@"[ERROR] osascript failed (%d): %@", task.terminationStatus,
              [errStr stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]);
        return NO;
    }
    return YES;
}

- (void)sendChunkedReply:(NSString *)body toRecipient:(NSString *)recipient isGroup:(BOOL)isGroup chatGuid:(NSString *)chatGuid {
    NSString *full = [body hasPrefix:@"🤖 "] ? body : [NSString stringWithFormat:@"🤖 AGY:\n%@", body];
    NSMutableArray<NSString *> *chunks = [NSMutableArray array];
    NSString *curr = full;

    while ((NSInteger)curr.length > self.maxReplyLength) {
        NSRange nlRange = [curr rangeOfString:@"\n" options:NSBackwardsSearch range:NSMakeRange(0, (NSUInteger)self.maxReplyLength)];
        NSUInteger splitIdx = (nlRange.location != NSNotFound && (NSInteger)nlRange.location > self.maxReplyLength / 2)
            ? nlRange.location
            : (NSUInteger)self.maxReplyLength;
        [chunks addObject:[[curr substringToIndex:splitIdx] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]];
        curr = [[curr substringFromIndex:splitIdx] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    }
    if (curr.length > 0) [chunks addObject:curr];

    for (NSUInteger idx = 0; idx < chunks.count; idx++) {
        NSString *chunkMsg = chunks[idx];
        if (chunks.count > 1) {
            NSString *cleanChunk = [chunkMsg hasPrefix:@"🤖 AGY:\n"] ? [chunkMsg substringFromIndex:[@"🤖 AGY:\n" length]] : chunkMsg;
            chunkMsg = [NSString stringWithFormat:@"🤖 (%lu/%lu)\n%@", (unsigned long)(idx + 1), (unsigned long)chunks.count, cleanChunk];
        }
        BOOL sent = [self sendIMessageTo:recipient text:chunkMsg isGroup:isGroup chatGuid:chatGuid];
        NSLog(@"[INFO] Sent chunk %lu/%lu to %@ (ok=%d, chars=%lu)",
              (unsigned long)(idx + 1), (unsigned long)chunks.count,
              chatGuid.length > 0 ? chatGuid : recipient, sent, (unsigned long)chunkMsg.length);
        if (idx + 1 < chunks.count) {
            [NSThread sleepForTimeInterval:0.8];
        }
    }
}

- (NSDictionary *)classifyRow:(NSDictionary *)row {
    int64_t rowId = [row[@"rowid"] longLongValue];
    if ([self.consumedRowIds containsObject:@(rowId)]) {
        return nil;
    }

    NSString *text = [row[@"text"] ?: @"" stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (text.length == 0 || [self isSelfEcho:text]) {
        return nil;
    }

    int isFromMe = [row[@"is_from_me"] intValue];
    NSString *handleId = row[@"handle_id"] ?: @"";
    NSString *chatIdentifier = row[@"chat_identifier"] ?: @"";
    NSString *chatGuid = row[@"chat_guid"] ?: @"";
    int chatStyle = [row[@"chat_style"] intValue];
    NSString *service = [row[@"service"] ?: @"" lowercaseString];
    int64_t msgDate = [row[@"date"] longLongValue];

    // Reject unauthenticated carrier SMS / RCS rows when receiving incoming messages
    if (isFromMe == 0 && self.allowedServices.count > 0) {
        if (service.length == 0 || ![self.allowedServices containsObject:service]) {
            NSLog(@"[SECURITY] Ignoring row %lld from '%@' on non-whitelisted service '%@'", rowId, handleId, service);
            return nil;
        }
    }

    // Ignore stale queued messages older than MAX_MESSAGE_AGE_SECONDS (Apple Cocoa epoch = Unix - 978307200, in ns)
    if (msgDate > 100000000000000LL && self.maxMessageAgeSeconds > 0) {
        NSTimeInterval msgUnix = ((double)msgDate / 1e9) + 978307200.0;
        NSTimeInterval ageSec = [[NSDate date] timeIntervalSince1970] - msgUnix;
        if (ageSec > self.maxMessageAgeSeconds) {
            NSLog(@"[SECURITY] Skipping stale message ROWID %lld (age=%0.0fs > max=%0.0fs)", rowId, ageSec, self.maxMessageAgeSeconds);
            return nil;
        }
    }

    BOOL isGroup = (chatStyle == 43) || [chatGuid containsString:@";+;chat"] || [chatIdentifier.lowercaseString hasPrefix:@"chat"];

    NSString *senderHandle = nil;
    NSString *replyHandle = nil;

    if (isFromMe == 1) {
        NSString *adminDefault = [self primaryAdminDefaultHandle];
        if (adminDefault.length == 0) return nil;
        senderHandle = adminDefault;
        if (isGroup) {
            replyHandle = senderHandle;
        } else {
            replyHandle = chatIdentifier.length > 0 ? chatIdentifier : (handleId.length > 0 ? handleId : senderHandle);
            if (![self isWhitelisted:replyHandle]) return nil;
        }
    } else {
        senderHandle = handleId.length > 0 ? handleId : chatIdentifier;
        if (![self isWhitelisted:senderHandle]) return nil;
        replyHandle = senderHandle;
    }

    BOOL isPrivateWithAdmin = (!isGroup) && [self isPrimaryAdmin:senderHandle] && [self isPrimaryAdmin:replyHandle];

    NSString *contextKey = nil;
    if (isGroup && chatGuid.length > 0) {
        contextKey = chatGuid;
    } else if (isPrivateWithAdmin) {
        contextKey = @"admin-1on1";
    } else {
        contextKey = chatGuid.length > 0 ? chatGuid : [NSString stringWithFormat:@"dm-%@", [BridgeDaemon normalizeHandle:replyHandle]];
    }

    return @{
        @"rowid": @(rowId),
        @"raw_text": text,
        @"is_from_me": @(isFromMe),
        @"sender_handle": senderHandle,
        @"reply_handle": replyHandle,
        @"is_group": @(isGroup),
        @"chat_guid": chatGuid,
        @"is_private_with_admin": @(isPrivateWithAdmin),
        @"context_key": contextKey
    };
}

- (NSString *)extractPromptFromText:(NSString *)text isFromMe:(int)isFromMe isGroup:(BOOL)isGroup {
    NSString *lower = text.lowercaseString;
    NSString *prompt = nil;

    for (NSString *prefix in self.triggerPrefixes) {
        if ([lower hasPrefix:prefix.lowercaseString]) {
            prompt = [text substringFromIndex:prefix.length];
            break;
        }
    }

    if (!prompt) {
        for (NSString *kw in self.midsentenceKeywords) {
            NSRange r = [text rangeOfString:kw options:NSCaseInsensitiveSearch];
            if (r.location != NSNotFound) {
                NSString *before = [[text substringToIndex:r.location] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                NSString *after = [[text substringFromIndex:r.location + r.length] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                prompt = [NSString stringWithFormat:@"%@ %@", before, after];
                break;
            }
        }
    }

    if (!prompt) {
        if (self.requirePrefix || isFromMe || isGroup) return nil;
        prompt = text;
    }

    while (prompt.length > 0) {
        unichar c = [prompt characterAtIndex:0];
        if (c == ',' || c == ':' || c == ';' || c == '-' || c == '@' || c == ' ' || c == '\t') {
            prompt = [prompt substringFromIndex:1];
        } else {
            break;
        }
    }
    prompt = [prompt stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    return prompt.length > 0 ? prompt : nil;
}

- (NSString *)formatRelativeAge:(NSString *)rawIso {
    if (!rawIso || rawIso.length < 16) return @"recent";
    // Parse "YYYY-MM-DD HH:MM:SS" prefix in UTC (SQLite last_modified_time)
    NSString *prefix19 = [rawIso substringToIndex:MIN((NSUInteger)19, rawIso.length)];
    prefix19 = [prefix19 stringByReplacingOccurrencesOfString:@"T" withString:@" "];

    static NSDateFormatter *df = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        df = [[NSDateFormatter alloc] init];
        df.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        df.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
        df.dateFormat = @"yyyy-MM-dd HH:mm:ss";
    });

    NSDate *dt = [df dateFromString:prefix19];
    if (!dt) return [rawIso substringToIndex:MIN((NSUInteger)16, rawIso.length)];
    NSTimeInterval delta = MAX(0.0, [[NSDate date] timeIntervalSinceDate:dt]);
    NSInteger secs = (NSInteger)delta;
    if (secs < 60) return [NSString stringWithFormat:@"%lds ago", (long)secs];
    if (secs < 3600) return [NSString stringWithFormat:@"%ldm ago", (long)(secs / 60)];
    if (secs < 86400) return [NSString stringWithFormat:@"%ldh ago", (long)(secs / 3600)];
    return [NSString stringWithFormat:@"%ldd ago", (long)(secs / 86400)];
}

- (NSArray<NSDictionary *> *)queryRecentConversationsWithLimit:(int)limit {
    NSMutableArray<NSDictionary *> *results = [NSMutableArray array];
    NSString *sumDbPath = [NSHomeDirectory() stringByAppendingPathComponent:@".gemini/antigravity-cli/conversation_summaries.db"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:sumDbPath]) {
        return results;
    }

    sqlite3 *db = NULL;
    NSString *uri = [NSString stringWithFormat:@"file:%@?mode=ro", sumDbPath];
    if (sqlite3_open_v2([uri UTF8String], &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return results;
    }
    sqlite3_busy_timeout(db, 2000);

    const char *sql =
        "SELECT conversation_id, title, preview, step_count, last_modified_time "
        "FROM conversation_summaries "
        "WHERE nesting_depth = 0 AND killed = 0 "
        "ORDER BY last_modified_time DESC LIMIT ?;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, limit > 0 ? limit : 10);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *cCid = (const char *)sqlite3_column_text(stmt, 0);
            const char *cTitle = (const char *)sqlite3_column_text(stmt, 1);
            const char *cPrev = (const char *)sqlite3_column_text(stmt, 2);
            int steps = sqlite3_column_int(stmt, 3);
            const char *cLmt = (const char *)sqlite3_column_text(stmt, 4);

            NSString *cid = cCid ? ([NSString stringWithUTF8String:cCid] ?: @"") : @"";
            if (!isValidUUID(cid)) continue;

            NSString *title = cTitle ? ([NSString stringWithUTF8String:cTitle] ?: @"") : @"";
            NSString *preview = cPrev ? ([NSString stringWithUTF8String:cPrev] ?: @"") : @"";
            NSString *lmt = cLmt ? ([NSString stringWithUTF8String:cLmt] ?: @"") : @"";

            NSString *label = title.length > 0 ? title : (preview.length > 0 ? preview : @"(Untitled session)");
            label = [[label componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]].firstObject
                     stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            if (label.length > 44) label = [[label substringToIndex:41] stringByAppendingString:@"..."];

            [results addObject:@{
                @"id": cid,
                @"title": label,
                @"steps": @(steps),
                @"age": [self formatRelativeAge:lmt]
            }];
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return results;
}

- (NSDictionary *)lookupConversationByPrefix:(NSString *)prefix {
    NSString *clean = [[prefix ?: @"" stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] lowercaseString];
    if (clean.length < 4) return nil;
    for (NSUInteger i = 0; i < clean.length; i++) {
        unichar c = [clean characterAtIndex:i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == '-')) return nil;
    }

    NSString *sumDbPath = [NSHomeDirectory() stringByAppendingPathComponent:@".gemini/antigravity-cli/conversation_summaries.db"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:sumDbPath]) {
        sqlite3 *db = NULL;
        NSString *uri = [NSString stringWithFormat:@"file:%@?mode=ro", sumDbPath];
        if (sqlite3_open_v2([uri UTF8String], &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) == SQLITE_OK) {
            sqlite3_busy_timeout(db, 2000);
            const char *sql =
                "SELECT conversation_id, title, preview, step_count, last_modified_time "
                "FROM conversation_summaries "
                "WHERE lower(conversation_id) LIKE ? "
                "ORDER BY last_modified_time DESC LIMIT 1;";
            sqlite3_stmt *stmt = NULL;
            if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                NSString *likePat = [NSString stringWithFormat:@"%@%%", clean];
                sqlite3_bind_text(stmt, 1, [likePat UTF8String], -1, SQLITE_TRANSIENT);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    const char *cCid = (const char *)sqlite3_column_text(stmt, 0);
                    const char *cTitle = (const char *)sqlite3_column_text(stmt, 1);
                    const char *cPrev = (const char *)sqlite3_column_text(stmt, 2);
                    int steps = sqlite3_column_int(stmt, 3);
                    const char *cLmt = (const char *)sqlite3_column_text(stmt, 4);

                    NSString *cid = cCid ? ([NSString stringWithUTF8String:cCid] ?: @"") : @"";
                    NSString *title = cTitle ? ([NSString stringWithUTF8String:cTitle] ?: @"") : @"";
                    NSString *preview = cPrev ? ([NSString stringWithUTF8String:cPrev] ?: @"") : @"";
                    NSString *lmt = cLmt ? ([NSString stringWithUTF8String:cLmt] ?: @"") : @"";
                    NSString *label = title.length > 0 ? title : (preview.length > 0 ? preview : @"(Untitled session)");
                    label = [[label componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]].firstObject
                             stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                    sqlite3_finalize(stmt);
                    sqlite3_close(db);
                    if (isValidUUID(cid)) {
                        return @{@"id": cid, @"title": label, @"steps": @(steps), @"age": [self formatRelativeAge:lmt]};
                    }
                    return nil;
                }
                sqlite3_finalize(stmt);
            }
            sqlite3_close(db);
        } else if (db) {
            sqlite3_close(db);
        }
    }

    NSString *brainDir = [NSHomeDirectory() stringByAppendingPathComponent:@".gemini/antigravity-cli/brain"];
    NSArray<NSString *> *entries = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:brainDir error:nil];
    for (NSString *entry in entries) {
        if (isValidUUID(entry) && [entry.lowercaseString hasPrefix:clean]) {
            return @{@"id": entry, @"title": @"(CLI session)", @"steps": @(0), @"age": @"recent"};
        }
    }
    return nil;
}

- (BOOL)handleBuiltinCommand:(NSString *)prompt
                     forItem:(NSDictionary *)item
           outImmediateReply:(NSString **)outReply
           outFollowupPrompt:(NSString **)outFollowup {
    NSString *trimmed = [prompt stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (trimmed.length == 0) return NO;

    NSRange sp = [trimmed rangeOfCharacterFromSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSString *cmd = (sp.location == NSNotFound) ? trimmed.lowercaseString : [[trimmed substringToIndex:sp.location] lowercaseString];
    NSString *rest = (sp.location == NSNotFound) ? @"" : [[trimmed substringFromIndex:sp.location + 1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

    NSString *ctx = item[@"context_key"];
    BOOL isAdmin = [item[@"is_private_with_admin"] boolValue];

    // 1. /new, /clear, /reset
    if ([self.resetChatCommands containsObject:cmd]) {
        NSString *prev = self.sessions[ctx];
        [self.sessions removeObjectForKey:ctx];
        NSMutableArray<NSDictionary *> *kept = [NSMutableArray array];
        for (NSDictionary *e in self.recentProcessedPrompts) {
            if (![e[@"context"] isEqualToString:ctx] || [e[@"is_cmd"] boolValue]) {
                [kept addObject:e];
            }
        }
        self.recentProcessedPrompts = kept;
        [self saveState];
        NSLog(@"[SESSION] Reset chat context '%@' (previous=%@)", ctx, prev ?: @"none");
        if (rest.length > 0) {
            if (outFollowup) *outFollowup = rest;
            return YES;
        }
        if (outReply) *outReply = @"🤖 AGY: 🆕 Started a fresh chat context.";
        return YES;
    }

    // 2. /resume (1:1 Primary Admin ONLY)
    if ([cmd isEqualToString:@"/resume"]) {
        if (!isAdmin) {
            if (outReply) *outReply = @"🤖 AGY: 🔒 /resume is restricted to 1:1 administrator chat.";
            return YES;
        }

        NSArray<NSDictionary *> *recent = [self queryRecentConversationsWithLimit:10];
        NSString *activeId = self.sessions[ctx] ?: @"";

        if (rest.length == 0 || [rest.lowercaseString isEqualToString:@"list"]) {
            if (recent.count == 0) {
                if (outReply) *outReply = @"🤖 AGY: No saved AGY conversations found on this host yet.";
                return YES;
            }
            [self.lastResumeList removeAllObjects];
            NSMutableArray<NSString *> *lines = [NSMutableArray arrayWithObject:@"🤖 AGY Recent Sessions:"];
            for (NSUInteger i = 0; i < recent.count; i++) {
                NSDictionary *r = recent[i];
                NSString *cid = r[@"id"];
                [self.lastResumeList addObject:cid];
                NSString *mark = [cid isEqualToString:activeId] ? @" 👈" : @"";
                NSString *shortId = [cid substringToIndex:8];
                [lines addObject:[NSString stringWithFormat:@"• %lu. %@%@\n  (%@ steps · %@ · %@)",
                                  (unsigned long)(i + 1), r[@"title"], mark, r[@"steps"], r[@"age"], shortId]];
            }
            [self saveState];
            [lines addObject:@"\nReply \"@agy /resume <#>\" or \"@agy /resume <id> [prompt]\""];
            if (outReply) *outReply = [lines componentsJoinedByString:@"\n"];
            return YES;
        }

        NSRange subSp = [rest rangeOfCharacterFromSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        NSString *selector = (subSp.location == NSNotFound) ? rest : [rest substringToIndex:subSp.location];
        NSString *trailing = (subSp.location == NSNotFound) ? @"" : [[rest substringFromIndex:subSp.location + 1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if ([selector hasPrefix:@"#"]) selector = [selector substringFromIndex:1];

        BOOL allDigits = selector.length > 0;
        for (NSUInteger i = 0; i < selector.length; i++) {
            unichar c = [selector characterAtIndex:i];
            if (c < '0' || c > '9') { allDigits = NO; break; }
        }

        NSDictionary *chosen = nil;
        if (allDigits) {
            NSInteger idx = [selector integerValue] - 1;
            NSArray<NSString *> *pool = self.lastResumeList.count > 0 ? self.lastResumeList : [recent valueForKey:@"id"];
            if (idx >= 0 && (NSUInteger)idx < pool.count) {
                chosen = [self lookupConversationByPrefix:pool[(NSUInteger)idx]];
            }
            if (!chosen) {
                if (outReply) *outReply = [NSString stringWithFormat:@"🤖 AGY: ⚠️ Session #%@ out of range. Run \"@agy /resume\" first.", selector];
                return YES;
            }
        } else {
            chosen = [self lookupConversationByPrefix:selector];
            if (!chosen) {
                if (outReply) *outReply = [NSString stringWithFormat:@"🤖 AGY: ⚠️ No conversation matching '%@'. Run \"@agy /resume\" to list.", selector];
                return YES;
            }
        }

        self.sessions[ctx] = chosen[@"id"];
        [self saveState];
        NSLog(@"[SESSION] Admin resumed conversation %@ ('%@') in '%@'", chosen[@"id"], chosen[@"title"], ctx);
        if (trailing.length > 0) {
            if (outFollowup) *outFollowup = trailing;
            return YES;
        }
        if (outReply) {
            *outReply = [NSString stringWithFormat:@"🤖 AGY: 🔄 Resumed session:\n\"%@\"\n(%@ · %@ steps)",
                         chosen[@"title"], [chosen[@"id"] substringToIndex:8], chosen[@"steps"]];
        }
        return YES;
    }

    // 3. /status or /session
    if ([cmd isEqualToString:@"/status"] || [cmd isEqualToString:@"/session"]) {
        NSString *activeId = self.sessions[ctx];
        NSString *shortId = (activeId.length >= 8) ? [activeId substringToIndex:8] : @"(new on next message)";
        NSString *tier = isAdmin ? @"Admin 1:1 (Interactive Approval)" : @"Restricted (Read-Only Sandbox)";
        BOOL sbx = isAdmin ? self.adminSandbox : self.restrictedSandbox;
        if (outReply) {
            *outReply = [NSString stringWithFormat:@"🤖 AGY Session Status:\n• Tier: %@\n• Session: %@\n• Sandbox: %@",
                         tier, shortId, sbx ? @"ON" : @"OFF"];
        }
        return YES;
    }

    // 4. /reload (1:1 Admin)
    if ([cmd isEqualToString:@"/reload"]) {
        if (!isAdmin) {
            if (outReply) *outReply = @"🤖 AGY: 🔒 /reload is restricted to 1:1 administrator chat.";
            return YES;
        }
        [self reloadEnvIfNeeded:YES];
        if (outReply) {
            *outReply = [NSString stringWithFormat:@"🤖 AGY: 🔄 Reloaded .env!\n• Ask Destructive: %@\n• Ask Secrets: %@\n• Timeout: %@",
                         self.adminAskDestructive, self.adminAskSecrets, self.agyPrintTimeout];
        }
        return YES;
    }

    // 5. /help
    if ([cmd isEqualToString:@"/help"]) {
        NSMutableArray<NSString *> *lines = [NSMutableArray arrayWithObjects:
            @"🤖 AGY Commands:",
            @"• @agy /new — Fresh chat context",
            @"• @agy /status — Current session info",
            nil];
        if (isAdmin) {
            [lines addObject:@"• @agy /resume — List & switch sessions"];
            [lines addObject:@"• @agy /resume <#> [msg] — Resume session"];
            [lines addObject:@"• @agy /reload — Hot-reload .env"];
        }
        if (outReply) *outReply = [lines componentsJoinedByString:@"\n"];
        return YES;
    }

    return NO;
}

- (NSNumber *)parseApprovalDecision:(NSString *)rawText expectedCode:(NSString *)expectedCode {
    NSString *cleaned = [[rawText ?: @"" stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] lowercaseString];
    for (NSString *pfx in [self.triggerPrefixes arrayByAddingObjectsFromArray:self.midsentenceKeywords]) {
        if ([cleaned hasPrefix:pfx.lowercaseString]) {
            cleaned = [[cleaned substringFromIndex:pfx.length] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        }
    }
    NSCharacterSet *punct = [NSCharacterSet characterSetWithCharactersInString:@",:;-!.? \t\"'"];
    cleaned = [cleaned stringByTrimmingCharactersInSet:punct];
    NSArray<NSString *> *words = [cleaned componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSString *firstWord = words.firstObject ?: @"";

    static NSSet<NSString *> *approveSet = nil;
    static NSSet<NSString *> *denySet = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        approveSet = [NSSet setWithObjects:@"yes", @"y", @"approve", @"approved", @"allow", @"proceed", @"confirm", nil];
        denySet = [NSSet setWithObjects:@"no", @"n", @"deny", @"denied", @"cancel", @"stop", @"reject", @"abort", nil];
    });

    if ([denySet containsObject:firstWord]) return @NO;

    if (expectedCode.length > 0 && [firstWord isEqualToString:expectedCode.lowercaseString]) {
        return @YES;
    }

    if ([approveSet containsObject:firstWord]) {
        if (self.requireApprovalCode && expectedCode.length > 0) {
            if ([cleaned containsString:expectedCode.lowercaseString]) {
                return @YES;
            }
            return nil;
        }
        return @YES;
    }
    return nil;
}

- (NSNumber *)pollAdminApprovalDecisionSinceCursor:(int64_t *)ioCursor expectedCode:(NSString *)expectedCode {
    NSArray<NSDictionary *> *rows = [self fetchMessagesSinceRowId:*ioCursor limit:50];
    for (NSDictionary *row in rows) {
        int64_t rid = [row[@"rowid"] longLongValue];
        if (rid > *ioCursor) *ioCursor = rid;

        NSDictionary *classified = [self classifyRow:row];
        if (!classified || ![classified[@"is_private_with_admin"] boolValue]) continue;

        NSNumber *decision = [self parseApprovalDecision:classified[@"raw_text"] expectedCode:expectedCode];
        if (decision != nil) {
            [self recordConsumedRowId:rid];
            self.lastApprovalReplyTimestamp = [[NSDate date] timeIntervalSince1970];
            NSLog(@"[APPROVAL] Captured Admin iMessage reply (ROWID %lld): approved=%d", rid, decision.boolValue);
            return decision;
        }
    }
    return nil;
}

- (void)parseAgyJsonOutput:(NSString *)stdoutStr outConvId:(NSString **)outConvId outResponse:(NSString **)outResponse {
    NSString *trimmed = [stdoutStr stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (trimmed.length == 0) {
        if (outResponse) *outResponse = @"";
        return;
    }

    NSMutableArray<NSString *> *candidates = [NSMutableArray arrayWithObject:trimmed];
    NSArray<NSString *> *lines = [trimmed componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    for (NSString *ln in [lines reverseObjectEnumerator]) {
        NSString *cl = [ln stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if ([cl hasPrefix:@"{"]) [candidates addObject:cl];
    }

    for (NSString *cand in candidates) {
        NSData *d = [cand dataUsingEncoding:NSUTF8StringEncoding];
        if (!d) continue;
        NSDictionary *obj = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
        if ([obj isKindOfClass:[NSDictionary class]] && (obj[@"response"] || obj[@"conversation_id"] || obj[@"conversationId"])) {
            NSString *cid = obj[@"conversation_id"] ?: obj[@"conversationId"];
            if ([cid isKindOfClass:[NSString class]] && isValidUUID(cid) && outConvId) {
                *outConvId = cid;
            }
            NSString *resp = [obj[@"response"] isKindOfClass:[NSString class]] ? obj[@"response"] : @"";
            if (outResponse) {
                *outResponse = [resp stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            }
            return;
        }
    }

    if (outResponse) *outResponse = trimmed;
}

- (NSString *)runAgyTurnWithPrompt:(NSString *)prompt
                           forItem:(NSDictionary *)item
                 outApprovedSecret:(BOOL *)outApprovedSecret {
    if (outApprovedSecret) *outApprovedSecret = NO;

    BOOL isAdmin = [item[@"is_private_with_admin"] boolValue];
    NSString *ctx = item[@"context_key"];
    NSString *replyHandle = item[@"reply_handle"];
    NSString *activeConvId = self.sessions[ctx];

    NSString *workspace = isAdmin ? self.adminWorkspaceDir : self.restrictedWorkspaceDir;
    NSString *settingsPath = isAdmin ? self.adminSettingsPath : self.restrictedSettingsPath;
    BOOL useSandbox = isAdmin ? self.adminSandbox : self.restrictedSandbox;
    NSString *modelOverride = isAdmin ? self.modelAdmin : self.modelRestricted;

    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (!([fm fileExistsAtPath:workspace isDirectory:&isDir] && isDir)) {
        NSLog(@"[WARNING] Workspace %@ missing; falling back to %@", workspace, self.baseDir);
        workspace = self.baseDir;
    }

    NSString *finalPrompt = prompt;
    if (!isAdmin) {
        finalPrompt = [NSString stringWithFormat:
            @"[CONFIDENTIALITY & READ-ONLY POLICY: Non-Admin / Shared Chat. Strictly read-only inspection. NEVER output passwords, tokens, API keys, .env values, or SSH keys.]\n\n%@",
            prompt];
    }

    NSMutableArray<NSString *> *args = [NSMutableArray arrayWithObjects:
        @"-p", finalPrompt,
        @"--output-format", @"json",
        @"--print-timeout", self.agyPrintTimeout,
        nil];

    if (activeConvId && isValidUUID(activeConvId)) {
        [args addObject:@"--conversation"];
        [args addObject:activeConvId];
    }
    if (self.disableSlashCommands) {
        [args addObject:@"--disable-slash-commands"];
    }
    if (useSandbox) {
        [args addObject:@"--sandbox"];
    }
    if ([fm fileExistsAtPath:settingsPath]) {
        [args addObject:@"--settings"];
        [args addObject:settingsPath];
    }
    if (modelOverride.length > 0) {
        [args addObject:@"--model"];
        [args addObject:modelOverride];
    }

    NSString *approvalToken = isAdmin ? [[NSUUID UUID] UUIDString] : @"";
    NSDictionary *parentEnv = [[NSProcessInfo processInfo] environment];
    NSString *localBin = [NSHomeDirectory() stringByAppendingPathComponent:@".local/bin"];
    NSString *childPath = [NSString stringWithFormat:@"%@:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", localBin];
    NSMutableDictionary<NSString *, NSString *> *childEnv = [NSMutableDictionary dictionaryWithDictionary:@{
        @"HOME": NSHomeDirectory(),
        @"USER": NSUserName(),
        @"LOGNAME": NSUserName(),
        @"PATH": childPath,
        @"LANG": parentEnv[@"LANG"] ?: @"en_US.UTF-8",
        @"TMPDIR": parentEnv[@"TMPDIR"] ?: @"/tmp",
        @"AGY_SESSION_ROLE": isAdmin ? @"admin" : @"restricted",
        @"AGY_EXTRA_ALLOWED_COMMANDS": self.extraAllowedCommands ?: @"",
        @"AGY_EXTRA_BLOCKED_PATHS": self.extraBlockedPaths ?: @"",
        @"AGY_ALLOWED_READ_ROOTS": self.allowedReadRoots ?: @""
    }];

    if (isAdmin) {
        [self prepareApprovalDirectory];
        childEnv[@"AGY_APPROVAL_DIR"] = self.approvalDir;
        childEnv[@"AGY_APPROVAL_TOKEN"] = approvalToken;
        childEnv[@"AGY_APPROVAL_TIMEOUT"] = [NSString stringWithFormat:@"%ld", (long)self.approvalTimeoutSeconds];
        childEnv[@"AGY_ADMIN_ASK_DESTRUCTIVE"] = self.adminAskDestructive ?: @"true";
        childEnv[@"AGY_ADMIN_ASK_SECRETS"] = self.adminAskSecrets ?: @"true";
    }

    NSLog(@"[AGY] Dispatching (role=%@, sandbox=%d, disclaimTcc=%d, conv=%@): '%@'",
          childEnv[@"AGY_SESSION_ROLE"],
          useSandbox,
          self.disclaimChildTcc,
          (activeConvId.length >= 8) ? [activeConvId substringToIndex:8] : @"NEW",
          prompt.length > 70 ? [[prompt substringToIndex:70] stringByAppendingString:@"..."] : prompt);

    NSPipe *outPipe = [NSPipe pipe];
    NSPipe *errPipe = [NSPipe pipe];
    int outReadFd = [[outPipe fileHandleForReading] fileDescriptor];
    int outWriteFd = [[outPipe fileHandleForWriting] fileDescriptor];
    int errReadFd = [[errPipe fileHandleForReading] fileDescriptor];
    int errWriteFd = [[errPipe fileHandleForWriting] fileDescriptor];

    posix_spawn_file_actions_t fileActions;
    posix_spawn_file_actions_init(&fileActions);
    posix_spawn_file_actions_adddup2(&fileActions, outWriteFd, STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&fileActions, errWriteFd, STDERR_FILENO);
    posix_spawn_file_actions_addclose(&fileActions, outReadFd);
    posix_spawn_file_actions_addclose(&fileActions, errReadFd);
    posix_spawn_file_actions_addclose(&fileActions, outWriteFd);
    posix_spawn_file_actions_addclose(&fileActions, errWriteFd);
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (@available(macOS 10.15, *)) {
        posix_spawn_file_actions_addchdir_np(&fileActions, [workspace fileSystemRepresentation]);
    }
    #pragma clang diagnostic pop

    posix_spawnattr_t spawnAttr;
    posix_spawnattr_init(&spawnAttr);
    if (self.disclaimChildTcc && responsibility_spawnattrs_setdisclaim != NULL) {
        responsibility_spawnattrs_setdisclaim(&spawnAttr, 1);
    }

    NSUInteger argcCount = args.count + 1;
    char **cArgv = (char **)calloc(argcCount + 1, sizeof(char *));
    cArgv[0] = strdup([self.agyBinary fileSystemRepresentation]);
    for (NSUInteger idx = 0; idx < args.count; idx++) {
        cArgv[idx + 1] = strdup([args[idx] UTF8String] ?: "");
    }
    cArgv[argcCount] = NULL;

    NSArray<NSString *> *envKeys = [childEnv allKeys];
    char **cEnvp = (char **)calloc(envKeys.count + 1, sizeof(char *));
    for (NSUInteger idx = 0; idx < envKeys.count; idx++) {
        NSString *k = envKeys[idx];
        NSString *kv = [NSString stringWithFormat:@"%@=%@", k, childEnv[k] ?: @""];
        cEnvp[idx] = strdup([kv UTF8String] ?: "");
    }
    cEnvp[envKeys.count] = NULL;

    pid_t childPid = 0;
    int spawnRc = posix_spawn(&childPid, [self.agyBinary fileSystemRepresentation], &fileActions, &spawnAttr, cArgv, cEnvp);

    posix_spawnattr_destroy(&spawnAttr);
    posix_spawn_file_actions_destroy(&fileActions);
    for (NSUInteger idx = 0; idx < argcCount; idx++) free(cArgv[idx]);
    free(cArgv);
    for (NSUInteger idx = 0; idx < envKeys.count; idx++) free(cEnvp[idx]);
    free(cEnvp);

    [[outPipe fileHandleForWriting] closeFile];
    [[errPipe fileHandleForWriting] closeFile];

    if (spawnRc != 0 || childPid <= 0) {
        [[outPipe fileHandleForReading] closeFile];
        [[errPipe fileHandleForReading] closeFile];
        return [NSString stringWithFormat:@"⚠️ Failed to spawn AGY binary at %@ (errno %d: %s)", self.agyBinary, spawnRc, strerror(spawnRc)];
    }

    NSMutableData *outData = [NSMutableData data];
    NSMutableData *errData = [NSMutableData data];
    NSUInteger capBytes = self.maxOutputBytes;

    dispatch_group_t drainGroup = dispatch_group_create();
    dispatch_group_async(drainGroup, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self drainFileHandle:[outPipe fileHandleForReading] intoData:outData maxBytes:capBytes];
        [[outPipe fileHandleForReading] closeFile];
    });
    dispatch_group_async(drainGroup, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self drainFileHandle:[errPipe fileHandleForReading] intoData:errData maxBytes:capBytes];
        [[errPipe fileHandleForReading] closeFile];
    });

    NSTimeInterval deadlineTs = [[NSDate date] timeIntervalSince1970] + self.agyTaskTimeout;
    NSMutableSet<NSString *> *promptedReqs = [NSMutableSet set];
    NSDictionary *activeReq = nil;
    int64_t approvalCursor = self.lastRowId;
    NSTimeInterval lastDbPollTs = 0.0;
    NSString *lastApprovalDbSig = nil;
    BOOL approvedSecretThisTurn = NO;
    int waitStatus = 0;
    BOOL childExited = NO;

    while (!childExited && !gShouldTerminate) {
        pid_t w = waitpid(childPid, &waitStatus, WNOHANG);
        if (w == childPid || (w == -1 && errno == ECHILD)) {
            childExited = YES;
            break;
        }

        NSTimeInterval nowTs = [[NSDate date] timeIntervalSince1970];
        if (nowTs > deadlineTs) {
            NSLog(@"[WARNING] AGY exceeded watchdog timeout; terminating PID %d", childPid);
            kill(childPid, SIGTERM);
            [NSThread sleepForTimeInterval:1.5];
            if (waitpid(childPid, &waitStatus, WNOHANG) == 0) {
                kill(childPid, SIGKILL);
                waitpid(childPid, &waitStatus, 0);
            }
            dispatch_group_wait(drainGroup, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)));
            return [NSString stringWithFormat:@"⏱️ AGY timed out after %0.0fs.", self.agyTaskTimeout];
        }

        if (isAdmin) {
            if (!activeReq) {
                NSArray<NSString *> *files = [[fm contentsOfDirectoryAtPath:self.approvalDir error:nil]
                                              sortedArrayUsingSelector:@selector(compare:)];
                for (NSString *fn in files) {
                    if (!([fn hasPrefix:@"req_"] && [fn hasSuffix:@".json"])) continue;
                    NSString *reqPath = [self.approvalDir stringByAppendingPathComponent:fn];
                    NSData *rd = [NSData dataWithContentsOfFile:reqPath];
                    if (!rd) continue;
                    NSDictionary *reqObj = [NSJSONSerialization JSONObjectWithData:rd options:0 error:nil];
                    if (![reqObj isKindOfClass:[NSDictionary class]]) continue;

                    NSString *rid = reqObj[@"id"];
                    NSString *tok = reqObj[@"token"];
                    if (![rid isKindOfClass:[NSString class]] || rid.length == 0 || [promptedReqs containsObject:rid]) continue;
                    if (![tok isKindOfClass:[NSString class]] || ![tok isEqualToString:approvalToken]) continue;

                    [promptedReqs addObject:rid];
                    activeReq = reqObj;
                    approvalCursor = MAX(self.lastRowId, [self queryMaxRowId]);

                    NSTimeInterval extended = nowTs + (NSTimeInterval)self.approvalTimeoutSeconds + self.agyTaskTimeout;
                    if (extended > deadlineTs) deadlineTs = extended;

                    BOOL isSecretReq = [reqObj[@"category"] isEqualToString:@"secret_access"];
                    NSString *catLabel = isSecretReq ? @"Secret / Credential Access" : @"State-Changing / Privileged Action";
                    NSString *summary = reqObj[@"summary"] ?: (reqObj[@"tool"] ?: @"tool");
                    NSString *reqCode = [reqObj[@"code"] isKindOfClass:[NSString class]] ? reqObj[@"code"] : @"";
                    NSString *replyInstr = (self.requireApprovalCode && reqCode.length > 0)
                        ? [NSString stringWithFormat:@"Reply \"YES %@\" within %lds to allow, or \"NO\" to deny.", reqCode, (long)self.approvalTimeoutSeconds]
                        : [NSString stringWithFormat:@"Reply YES (Y) within %lds to allow, or NO (N) to deny.", (long)self.approvalTimeoutSeconds];

                    NSString *msg = [NSString stringWithFormat:
                        @"🔐 AGY Permission Request\n• Type: %@\n• Action: %@\n\n%@",
                        catLabel, summary, replyInstr];

                    [self sendIMessageTo:replyHandle text:msg isGroup:NO chatGuid:@""];
                    lastApprovalDbSig = [self currentDbStateSignature];
                    NSLog(@"[APPROVAL] Sent interactive permission request %@ (code=%@, category=%@) to Admin", rid, reqCode, reqObj[@"category"]);
                    break;
                }
            } else {
                NSString *reqId = activeReq[@"id"];
                NSString *reqCode = [activeReq[@"code"] isKindOfClass:[NSString class]] ? activeReq[@"code"] : @"";
                NSString *reqPath = [self.approvalDir stringByAppendingPathComponent:[NSString stringWithFormat:@"req_%@.json", reqId]];
                if (![fm fileExistsAtPath:reqPath]) {
                    activeReq = nil;
                } else {
                    NSString *curSig = [self currentDbStateSignature];
                    if (![curSig isEqualToString:(lastApprovalDbSig ?: @"")] || (nowTs - lastDbPollTs >= 5.0)) {
                        lastApprovalDbSig = curSig;
                        lastDbPollTs = nowTs;
                        NSNumber *decision = [self pollAdminApprovalDecisionSinceCursor:&approvalCursor expectedCode:reqCode];
                        if (decision != nil) {
                            BOOL approved = decision.boolValue;
                            NSDictionary *respObj = @{
                                @"approved": @(approved),
                                @"token": approvalToken,
                                @"reason": approved ? @"Approved by administrator." : @"Denied by administrator via iMessage."
                            };
                            NSData *respBytes = [NSJSONSerialization dataWithJSONObject:respObj options:0 error:nil];
                            NSString *respTmp = [self.approvalDir stringByAppendingPathComponent:[NSString stringWithFormat:@".resp_%@.tmp", reqId]];
                            NSString *respFinal = [self.approvalDir stringByAppendingPathComponent:[NSString stringWithFormat:@"resp_%@.json", reqId]];
                            if (respBytes && [respBytes writeToFile:respTmp atomically:NO]) {
                                chmod([respTmp fileSystemRepresentation], S_IRUSR | S_IWUSR);
                                rename([respTmp fileSystemRepresentation], [respFinal fileSystemRepresentation]);
                            }

                            if (approved && [activeReq[@"category"] isEqualToString:@"secret_access"]) {
                                approvedSecretThisTurn = YES;
                            }
                            if (self.sendAck) {
                                [self sendIMessageTo:replyHandle
                                                text:(approved ? @"✅ Approved — executing..." : @"🛑 Denied.")
                                             isGroup:NO
                                            chatGuid:@""];
                            }
                            activeReq = nil;
                        }
                    }
                }
            }
        }
        [NSThread sleepForTimeInterval:0.25];
    }

    if (!childExited) {
        kill(childPid, SIGTERM);
        waitpid(childPid, &waitStatus, 0);
    }
    dispatch_group_wait(drainGroup, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)));
    int exitCode = WIFEXITED(waitStatus) ? WEXITSTATUS(waitStatus) : -1;

    NSString *outStr = [[NSString alloc] initWithData:outData encoding:NSUTF8StringEncoding] ?: @"";
    NSString *errStr = [[[NSString alloc] initWithData:errData encoding:NSUTF8StringEncoding] ?: @""
                        stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

    NSString *newCid = nil;
    NSString *parsedResp = nil;
    [self parseAgyJsonOutput:outStr outConvId:&newCid outResponse:&parsedResp];

    if (newCid.length > 0 && ![self.sessions[ctx] isEqualToString:newCid]) {
        self.sessions[ctx] = newCid;
        [self saveState];
    }

    if (outApprovedSecret) *outApprovedSecret = approvedSecretThisTurn;

    if (exitCode != 0 && parsedResp.length == 0) {
        NSLog(@"[ERROR] AGY exited with code %d. Stderr: %@", exitCode, errStr);
        NSString *detail = errStr.length > 0 ? errStr : outStr;
        if (detail.length > 600) detail = [detail substringToIndex:600];
        return [NSString stringWithFormat:@"⚠️ AGY error (code %d):\n%@", exitCode, detail];
    }

    return parsedResp.length > 0 ? parsedResp : @"(No output returned from AGY)";
}

- (void)waitForFullDiskAccess {
    while (!gShouldTerminate) {
        [self reloadEnvIfNeeded:NO];
        sqlite3 *testDb = NULL;
        NSString *uri = [NSString stringWithFormat:@"file:%@?mode=ro", self.dbPath];
        int rc = sqlite3_open_v2([uri UTF8String], &testDb, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_stmt *stmt = NULL;
            rc = sqlite3_prepare_v2(testDb, "SELECT count(*) FROM message;", -1, &stmt, NULL);
            if (rc == SQLITE_OK) {
                sqlite3_finalize(stmt);
                sqlite3_close(testDb);
                NSLog(@"[FDA] Read-only SQLite WAL access verified on %@", self.dbPath);
                return;
            }
        }
        if (testDb) sqlite3_close(testDb);

        NSLog(@"[CRITICAL] Access to chat.db denied by macOS TCC.\n"
              @"Please grant 'Full Disk Access' to this executable in:\n"
              @"  System Settings -> Privacy & Security -> Full Disk Access\n"
              @"  Binary: %@\n"
              @"Waiting 10 seconds...",
              [[NSBundle mainBundle] executablePath] ?: @"imessage-agy-daemon");
        for (int i = 0; i < 20 && !gShouldTerminate; i++) {
            [NSThread sleepForTimeInterval:0.5];
        }
    }
}

- (void)run {
    NSLog(@"=========================================================");
    NSLog(@"iMessage <-> Antigravity CLI Native Daemon (arm64 Obj-C)");
    NSLog(@"Base Dir: %@", self.baseDir);
    NSLog(@"Env File: %@ (auto hot-reload active)", self.envPath);
    NSLog(@"=========================================================");

    [self waitForFullDiskAccess];
    if (gShouldTerminate) return;

    [self loadState];

    while (!gShouldTerminate) {
        @autoreleasepool {
            [self reloadEnvIfNeeded:NO];
            [self maintainLogFilesIfNeeded:NO];

            if (self.normAllowed.count == 0) {
                NSLog(@"[WARNING] No ALLOWED_SENDERS or ADMIN_HANDLES configured in .env; waiting 5s...");
                [NSThread sleepForTimeInterval:5.0];
                continue;
            }

            NSString *currentSig = [self currentDbStateSignature];
            if (self.lastCheckedDbSignature && [currentSig isEqualToString:self.lastCheckedDbSignature]) {
                [self waitForDatabaseOrEnvChangeWithTimeout:self.pollInterval];
                continue;
            }
            self.lastCheckedDbSignature = currentSig;

            NSArray<NSDictionary *> *rows = [self fetchMessagesSinceRowId:self.lastRowId limit:200];
            if (rows.count > 0) {
                NSDictionary *lastRow = rows.lastObject;
                NSString *lastText = lastRow[@"text"] ?: @"";
                NSString *lastChatGuid = lastRow[@"chat_guid"] ?: @"";
                if (lastText.length == 0 || lastChatGuid.length == 0) {
                    // Wait 80ms in case imagent is mid-transaction writing attributedBody or chat_message_join
                    [NSThread sleepForTimeInterval:0.08];
                    self.lastCheckedDbSignature = [self currentDbStateSignature];
                    rows = [self fetchMessagesSinceRowId:self.lastRowId limit:200];
                }
            }
            NSMutableArray<NSDictionary *> *pending = [NSMutableArray array];

            for (NSDictionary *row in rows) {
                int64_t rid = [row[@"rowid"] longLongValue];
                if (rid > self.lastRowId) {
                    self.lastRowId = rid;
                    [self saveState];
                }

                NSDictionary *classified = [self classifyRow:row];
                if (!classified) continue;

                NSString *prompt = [self extractPromptFromText:classified[@"raw_text"]
                                                      isFromMe:[classified[@"is_from_me"] intValue]
                                                       isGroup:[classified[@"is_group"] boolValue]];
                if (!prompt) continue;

                // Suppress Note-to-Self dual-row echoes of standalone YES/NO/code within 12s of an approval reply
                NSTimeInterval sinceApproval = [[NSDate date] timeIntervalSince1970] - self.lastApprovalReplyTimestamp;
                if ([classified[@"is_private_with_admin"] boolValue] &&
                    sinceApproval <= 12.0 &&
                    [self parseApprovalDecision:prompt expectedCode:@""] != nil &&
                    [prompt componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]].count <= 2) {
                    continue;
                }

                NSMutableDictionary *item = [classified mutableCopy];
                item[@"prompt"] = prompt;
                [pending addObject:item];
            }

            for (NSUInteger i = 0; i < pending.count && !gShouldTerminate; i++) {
                NSDictionary *item = pending[i];
                NSString *prompt = item[@"prompt"];
                NSString *ctx = item[@"context_key"];

                if (![self isBuiltinCommand:prompt]) {
                    BOOL superseded = NO;
                    for (NSUInteger j = i + 1; j < pending.count; j++) {
                        NSDictionary *later = pending[j];
                        if ([later[@"context_key"] isEqualToString:ctx] && ![self isBuiltinCommand:later[@"prompt"]]) {
                            if ([self isPromptSimilar:prompt toRecent:later[@"prompt"]]) {
                                NSLog(@"[INFO] Coalescing batch in '%@': skipping '%@' in favor of '%@'", ctx, prompt, later[@"prompt"]);
                                superseded = YES;
                                break;
                            }
                        }
                    }
                    if (superseded) continue;
                }

                if ([self isDuplicatePrompt:prompt forContext:ctx]) {
                    continue;
                }
                if (![self checkRateLimitForContext:ctx]) {
                    NSLog(@"[SECURITY] Rate limit (%ld/min) exceeded for context '%@'", (long)self.maxRequestsPerMinute, ctx);
                    continue;
                }
                [self recordProcessedPrompt:prompt forContext:ctx];

                NSString *immediateReply = nil;
                NSString *followupPrompt = nil;
                if ([self handleBuiltinCommand:prompt forItem:item outImmediateReply:&immediateReply outFollowupPrompt:&followupPrompt]) {
                    if (immediateReply.length > 0) {
                        [self sendChunkedReply:immediateReply
                                   toRecipient:item[@"reply_handle"]
                                       isGroup:[item[@"is_group"] boolValue]
                                      chatGuid:item[@"chat_guid"]];
                    }
                    if (followupPrompt.length == 0) {
                        continue;
                    }
                    prompt = followupPrompt;
                }

                BOOL isGroup = [item[@"is_group"] boolValue];
                BOOL isAdmin = [item[@"is_private_with_admin"] boolValue];
                NSString *replyHandle = item[@"reply_handle"];
                NSString *chatGuid = item[@"chat_guid"];

                NSLog(@"[INFO] Processing command in '%@' from %@ (group=%d, admin1on1=%d): '%@'",
                      ctx, replyHandle, isGroup, isAdmin, prompt);

                if (self.sendAck) {
                    [self sendIMessageTo:replyHandle text:self.ackText isGroup:isGroup chatGuid:chatGuid];
                }

                NSDate *start = [NSDate date];
                BOOL approvedSecret = NO;
                NSString *response = [self runAgyTurnWithPrompt:prompt forItem:item outApprovedSecret:&approvedSecret];
                [self recordProcessedPrompt:prompt forContext:ctx];
                NSTimeInterval dur = [[NSDate date] timeIntervalSinceDate:start];
                NSLog(@"[INFO] AGY completed in %0.1fs (%lu chars, approvedSecret=%d)", dur, (unsigned long)response.length, approvedSecret);

                response = [self redactPrivateKeys:response];
                BOOL shouldRedact = !isAdmin
                    ? self.redactRestricted
                    : (self.redactAdminUnlessApproved && !approvedSecret);
                if (shouldRedact) {
                    response = [self redactSecrets:response];
                }

                [self sendChunkedReply:response toRecipient:replyHandle isGroup:isGroup chatGuid:chatGuid];
                [self maintainLogFilesIfNeeded:YES];
            }
        }
        [self waitForDatabaseOrEnvChangeWithTimeout:self.pollInterval];
    }
    NSLog(@"[INFO] Daemon exiting cleanly.");
}

@end

int main(int argc, const char * argv[]) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, handleSignal);
    signal(SIGINT, handleSignal);

    @autoreleasepool {
        NSString *baseDir = nil;
        for (int i = 1; i + 1 < argc; i++) {
            if (strcmp(argv[i], "--project-dir") == 0) {
                baseDir = [[NSString stringWithUTF8String:argv[i + 1]] stringByExpandingTildeInPath];
            }
        }
        if (!baseDir) {
            NSString *binaryPath = [[NSProcessInfo processInfo] arguments].firstObject;
            baseDir = [binaryPath stringByDeletingLastPathComponent];
        }
        BridgeDaemon *daemon = [[BridgeDaemon alloc] initWithBaseDir:baseDir];
        [daemon run];
    }
    return 0;
}
