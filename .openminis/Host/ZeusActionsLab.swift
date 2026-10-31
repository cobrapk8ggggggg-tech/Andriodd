import Foundation
import Combine
import CryptoKit
import Security

/// Actions is the runtime. Only a small receipt and a Keychain encryption key
/// survive on the device; frames and decrypted control results stay in memory.
@MainActor final class ZeusActionsLab: ObservableObject {
    struct Receipt: Codable {
        let session: UUID
        let owner: String
        let conversation: UUID
        let accountID: String
        let repository: String
        let branch: String
        var commit: String
        var runID: Int?
        var sequence: Int = 0
        var pendingRequest: String?
        var releaseID: Int?
    }
    struct Connection: Decodable {
        let session: UUID
        let owner: String
        let conversation: UUID
        let url: URL
        let deadline: TimeInterval
        let viewer_bootstrap: String
        let agent_bootstrap: String
        let control_public_key: String
    }
    struct SavedProject: Identifiable {
        let id:Int
        let title:String
        let assetID:Int
        let bytes:Int
        let sha256:String
        let final:Bool
    }
    private static var instances: [String: ZeusActionsLab] = [:]
    static func shared(_ conversation: UUID) -> ZeusActionsLab {
        let scope=(NativeCloudAccountAPI.ownerID ?? "signed-out")+"/"+conversation.uuidString.lowercased()
        if let current=instances[scope] { return current }
        let created=ZeusActionsLab(conversation:conversation);instances[scope]=created;return created
    }
    @Published private(set) var receipt: Receipt?
    @Published private(set) var connection: Connection?
    @Published private(set) var screenshot: Data?
    @Published private(set) var observedAt: Date?
    @Published private(set) var phase = "جاهز لبدء جلسة مؤقتة"
    @Published private(set) var busy = false
    @Published private(set) var completed = false
    @Published private(set) var savedProjects:[SavedProject] = []
    @Published private(set) var stream:[String:String]?
    @Published var issue: String?
    let conversation: UUID
    private var polling: Task<Void,Never>?
    private var pollingNow=false
    private var frameNumber = 0
    private var emergencyNumber = 200000
    private var emergencyResponses:[String:[String:Any]] = [:]
    private var takingControl = false
    private var writeTail:Task<Void,Never>?
    var isTrusted:Bool { lastState?["trusted"] as? Bool == true && lastState?["controller"] as? String == "agent" && !completed }
    var displayState: [String:Any]? { lastState }
    private(set) var networkEvents: [[String:Any]] = []
    private var lastHeartbeat=Date.distantPast
    private var nextStreamAttempt=Date.distantPast
    private var lastState: [String:Any]?
    private var pendingCount = 0
    private var requestTail: Task<Void,Never>?
    private var observations: [String:[String:Any]] = [:]
    private let client = ZeusGitHubTools.shared
    private var storageKey: String { "zeus.android.actions." + conversation.uuidString.lowercased() }
    private init(conversation:UUID) {
        self.conversation=conversation
        if let data=UserDefaults.standard.data(forKey:storageKey),let saved=try? JSONDecoder().decode(Receipt.self,from:data),saved.owner==NativeCloudAccountAPI.ownerID?.lowercased() { receipt=saved }
    }
    private func save() throws { if let receipt { UserDefaults.standard.set(try JSONEncoder().encode(receipt),forKey:storageKey) } }
    private func requireOwner() throws -> Receipt {
        guard let receipt,receipt.owner==NativeCloudAccountAPI.ownerID?.lowercased() else { connection=nil;stream=nil;screenshot=nil;lastState=nil;networkEvents=[];pause();throw ZeusPatch.failure("الجلسة تخص حساب ZEUS آخر أو انتهى تسجيل الدخول") }
        return receipt
    }
    private func keyQuery(_ receipt:Receipt)->[String:Any] {
        [kSecClass as String:kSecClassGenericPassword,kSecAttrService as String:"ZEUS.AndroidLab.X25519.v1",kSecAttrAccount as String:receipt.owner+"/"+receipt.session.uuidString.lowercased()]
    }
    private func privateKey(_ receipt:Receipt) throws -> Data {
        var query=keyQuery(receipt);query[kSecReturnData as String]=true;query[kSecMatchLimit as String]=kSecMatchLimitOne
        var result:CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary,&result)==errSecSuccess,let data=result as? Data,data.count==32 else { throw ZeusPatch.failure("مفتاح فك تشفير الجلسة غير متاح في Keychain؛ لا تبدأ جلسة بديلة فوق نتائج لم تحفظها") }
        return data
    }
    func start(accountID:String,repository:String,ref:String,trusted:Bool=true) async throws {
        guard !busy,receipt==nil || completed else { throw ZeusPatch.failure("توجد جلسة قائمة؛ أوقفها أو انتظر اكتمالها") }
        guard let owner=NativeCloudAccountAPI.ownerID?.lowercased(),UUID(uuidString:owner) != nil,
              repository.range(of:#"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"#,options:.regularExpression) != nil,
              !ref.isEmpty,!ref.contains(".."),ref.count<=200 else { throw ZeusPatch.failure("اختر حسابًا ومستودعًا وفرعًا صالحًا") }
        busy=true;defer { busy=false }
        let prefix="/repos/"+repository
        let repo=try await client.object(accountID:accountID,path:prefix)
        guard (repo["permissions"] as? [String:Any])?["push"] as? Bool==true else { throw ZeusPatch.failure("يلزم حساب GitHub بصلاحية الكتابة إلى هذا المستودع") }
        _ = try await client.readSource(accountID:accountID,repository:repository,branch:ref,path:".github/workflows/zeus-lab-tunnel.yml",maxChars:1000)
        let base=try await client.object(accountID:accountID,path:prefix+"/commits/"+ref)
        guard let sha=base["sha"] as? String,sha.count==40 else { throw ZeusPatch.failure("لم يتأكد مصدر الجلسة") }
        let session=UUID(),key=Curve25519.KeyAgreement.PrivateKey(),branch="zeus-lab/"+session.uuidString.lowercased()
        var created=Receipt(session:session,owner:owner,conversation:conversation,accountID:accountID,repository:repository,branch:branch,commit:sha)
        if repo["private"] as? Bool == true {
            let release=try await client.request(accountID:accountID,method:"POST",path:prefix+"/releases",body:["tag_name":"zeus-lab-"+session.uuidString.lowercased(),"target_commitish":sha,"name":"ZEUS Android Lab · "+conversation.uuidString.lowercased(),"body":"Temporary Android session outputs for ZEUS account "+owner+"; conversation "+conversation.uuidString.lowercased(),"draft":true])
            guard let identifier=(release["data"] as? [String:Any])?["id"] as? Int else { throw ZeusPatch.failure("لم يتأكد إنشاء أرشيف المشروع الخاص") }
            created.releaseID=identifier
        }
        var query=keyQuery(created);query[kSecValueData as String]=key.rawRepresentation;query[kSecAttrAccessible as String]=kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        guard SecItemAdd(query as CFDictionary,nil)==errSecSuccess else { throw ZeusPatch.failure("تعذر حفظ مفتاح الجلسة") }
        _ = try await client.request(accountID:accountID,method:"POST",path:prefix+"/git/refs",body:["ref":"refs/heads/"+branch,"sha":sha])
        receipt=created;completed=false;connection=nil;stream=nil;nextStreamAttempt = .distantPast;screenshot=nil;frameNumber=0;try save()
        var launch:[String:Any] = ["session":session.uuidString.lowercased(),"owner":owner,"conversation":conversation.uuidString.lowercased(),"public_key":key.publicKey.rawRepresentation.base64EncodedString(),"runtime_seconds":900,"fixture_only":false,"trusted":trusted,"purpose":"User-requested temporary Android security laboratory"]
        if let identifier=created.releaseID { launch["release_id"]=identifier;launch["private_archive"]=true }
        let content=String(decoding:try JSONSerialization.data(withJSONObject:launch,options:[.sortedKeys]),as:UTF8.self)+"\n"
        let result=try await client.writeSources(accountID:accountID,repository:repository,branch:branch,message:"Start temporary encrypted ZEUS Android laboratory",files:[["path":"experiments/actions-lab/launch.json","content":content],
            ["path":"experiments/actions-lab/control.json","content":"{\"sequence\":0}\n"],
            ["path":"experiments/actions-lab/emergency.json","content":"{\"sequence\":0}\n"]])
        guard let head=result["commit_sha"] as? String else { throw ZeusPatch.failure("تعذر تأكيد بدء الجلسة؛ افحص الفرع قبل إعادة المحاولة") }
        created.commit=head;receipt=created;try save();phase="يجري تجهيز Android على GitHub Actions…";resume()
    }
    func resume() {
        guard polling==nil,receipt != nil else { return }
        polling=Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { break }
                do { try await self.poll() } catch { self.issue=error.localizedDescription }
                if self.completed { break }
                try? await Task.sleep(for:.seconds(5))
            }
            self?.polling=nil
        }
    }
    func pause() { polling?.cancel();polling=nil }
    private func readArtifact(_ artifact:[String:Any],name:String,receipt:Receipt) async throws -> Data {
        guard let id=artifact["id"] as? Int,let size=artifact["size_in_bytes"] as? Int,size>0,size<6*1024*1024,artifact["expired"] as? Bool==false else { throw ZeusPatch.failure("ملف الجلسة انتهى أو يتجاوز حد القراءة") }
        let zip=try await client.downloadArtifact(accountID:receipt.accountID,repository:receipt.repository,artifactID:id)
        defer { try? FileManager.default.removeItem(at:zip) }
        let handle=try FileHandle(forReadingFrom:zip);defer { try? handle.close() }
        let entries=try BackupZipExtractor.centralDirectory(handle:handle).filter { $0.name==name || $0.name.hasSuffix("/"+name) }
        guard entries.count==1,entries[0].uncompressedSize<=4*1024*1024,entries[0].compressedSize<=4*1024*1024,
              let data=try BackupPackageReader.readEntry(at:zip,named:name) else { throw ZeusPatch.failure("مغلف الجلسة مفقود أو غير آمن") }
        let box=try JSONDecoder().decode(ZeusLabEnvelope.Box.self,from:data)
        return try ZeusLabEnvelope.open(box,using:privateKey(receipt),session:receipt.session)
    }
    private func frame(_ value:[String:Any]) {
        if let events=(value["network"] as? [String:Any])?["events"] as? [[String:Any]] { networkEvents=events }
        if let state=value["state"] as? [String:Any] ?? value["session"] as? [String:Any] { lastState=state }
        if let base64=value["screenshot"] as? String,base64.utf8.count<1_300_000,let data=Data(base64Encoded:base64),data.count<=900000 {
            screenshot=data;observedAt=(value["observed_at"] as? Double).map(Date.init(timeIntervalSince1970:))
        }
    }
    func poll() async throws {
        guard !pollingNow else { return };pollingNow=true;defer { pollingNow=false }
        var saved=try requireOwner();let prefix="/repos/"+saved.repository
        if saved.runID==nil {
            let result=try await client.object(accountID:saved.accountID,path:prefix+"/actions/runs",query:["branch":saved.branch,"per_page":"10"])
            if let run=(result["workflow_runs"] as? [[String:Any]])?.first(where: { $0["head_sha"] as? String==saved.commit && $0["path"] as? String==".github/workflows/zeus-lab-tunnel.yml" }),let id=run["id"] as? Int { saved.runID=id;receipt=saved;try save() }
            else { return }
        }
        guard let runID=saved.runID else { return }
        var artifacts:[[String:Any]]=[]
        for page in 1...3 {
            let result=try await client.object(accountID:saved.accountID,path:prefix+"/actions/runs/\(runID)/artifacts",query:["per_page":"100","page":String(page)])
            let values=result["artifacts"] as? [[String:Any]] ?? [];artifacts+=values
            if values.count<100 { break }
        }
        let stem="zeus-lab-\(runID)-1-"
        if connection==nil,let initial=artifacts.first(where: { $0["name"] as? String==stem+"0" }) {
            let access=try JSONDecoder().decode(Connection.self,from:await readArtifact(initial,name:"connection.sealed.json",receipt:saved))
            guard access.session==saved.session,access.owner.lowercased()==saved.owner,access.conversation==conversation,access.url.scheme=="https",access.url.user==nil,access.url.password==nil else { throw ZeusPatch.failure("بيانات الاتصال لا تطابق حساب الجلسة") }
            connection=access;phase="Android متصل · لقطات متتابعة مشفّرة";issue=nil
        }
        let frames=artifacts.compactMap { a -> (Int,[String:Any])? in
            guard let name=a["name"] as? String,name.hasPrefix(stem),let n=Int(name.dropFirst(stem.count)),n>=1001,n<200000,n>frameNumber else { return nil };return (n,a)
        }
        if let latest=frames.max(by: { $0.0<$1.0 }) {
            let value=try JSONSerialization.jsonObject(with:await readArtifact(latest.1,name:"frame.sealed.json",receipt:saved)) as? [String:Any] ?? [:]
            frame(value);frameNumber=latest.0
        }
        if let pending=saved.pendingRequest,let observation=artifacts.first(where: { $0["name"] as? String==stem+String(100+saved.sequence) }) {
            let value=try JSONSerialization.jsonObject(with:await readArtifact(observation,name:"observation.sealed.json",receipt:saved)) as? [String:Any] ?? [:]
            guard value["request_id"] as? String==pending,value["sequence"] as? Int==saved.sequence else { throw ZeusPatch.failure("لا تطابق نتيجة الأمر الطلب المنتظر") }
            observations[pending]=value;frame(value);saved.pendingRequest=nil;receipt=saved;try save()
            if observations.count>16 { observations=observations.filter { $0.key==pending } }
        }
        if let latest=artifacts.compactMap({ a -> (Int,[String:Any])? in
            guard let name=a["name"] as? String,name.hasPrefix(stem),let number=Int(name.dropFirst(stem.count)),number>emergencyNumber,number>=200001 else { return nil };return (number,a)
        }).max(by:{$0.0<$1.0}) {
            let value=try JSONSerialization.jsonObject(with:await readArtifact(latest.1,name:"emergency.sealed.json",receipt:saved)) as? [String:Any] ?? [:]
            if let request=value["request_id"] as? String { emergencyResponses[request]=value }
            emergencyNumber=latest.0
            if value["http_status"] as? Int==200,let result=value["result"] as? [String:Any] { lastState=result }
        }
        let run=try await client.object(accountID:saved.accountID,path:prefix+"/actions/runs/\(runID)")
        if run["status"] as? String=="completed" { completed=true;stream=nil;phase="انتهت الجلسة · "+(run["conclusion"] as? String ?? "غير محسوم") }
        else if connection != nil,Date()>=nextStreamAttempt { await refreshStream() }
    }
    private func refreshStream() async {
        nextStreamAttempt=Date().addingTimeInterval(60)
        guard let access=connection,access.url.scheme=="https",access.url.host?.hasSuffix(".trycloudflare.com")==true else { return }
        let configuration=URLSessionConfiguration.ephemeral;configuration.urlCache=nil;configuration.timeoutIntervalForRequest=8
        let transport=URLSession(configuration:configuration,delegate:ZeusLabNoRedirect(),delegateQueue:nil);defer { transport.invalidateAndCancel() }
        do {
            var url=URLComponents(url:access.url,resolvingAgainstBaseURL:false)!;url.path="/v1/access/renew";url.query=nil;url.fragment=nil
            var request=URLRequest(url:url.url!);request.httpMethod="POST";request.setValue("Bearer "+access.viewer_bootstrap,forHTTPHeaderField:"Authorization")
            let (raw,response)=try await transport.data(for:request)
            guard (response as? HTTPURLResponse)?.statusCode==200,let object=try JSONSerialization.jsonObject(with:raw) as? [String:Any],let token=object["token"] as? String else { stream=nil;return }
            stream=["preferred":"websocket","network_feed":"github_poll","stream_url":access.url.absoluteString,"stream_token":token];nextStreamAttempt=Date().addingTimeInterval(180)
        } catch { stream=nil }
    }
    func execute(_ name:String,args:[String:Any],requestID:String=UUID().uuidString.lowercased(),agent:Bool=false) async throws -> [String:Any] {
        let digest=Array(SHA256.hash(data:Data(requestID.utf8)).prefix(16)).map { String(format:"%02x",$0) }.joined()
        let canonical=String(digest.prefix(8))+"-"+String(digest.dropFirst(8).prefix(4))+"-"+String(digest.dropFirst(12).prefix(4))+"-"+String(digest.dropFirst(16).prefix(4))+"-"+String(digest.suffix(12))
        let requestID=UUID(uuidString:requestID)?.uuidString.lowercased() ?? canonical
        guard !busy else { throw ZeusPatch.failure("يوجد أمر قيد التنفيذ؛ انتظر نتيجته") }
        var saved=try requireOwner()
        guard let access=connection,!completed,access.deadline>Date().timeIntervalSince1970 else { throw ZeusPatch.failure("جلسة Android لم تبدأ أو انتهت مدتها") }
        guard saved.pendingRequest==nil else { throw ZeusPatch.failure("نتيجة الأمر السابق غير مؤكدة؛ يجري انتظارها ولن يتكرر الإجراء تلقائيًا") }
        busy=true;defer { busy=false }
        if !agent,let stream,let token=stream["stream_token"],ZeusAndroidTools.names.contains(name) {
            let result=try await directRequest(path:"/v1/tool",body:["name":name,"arguments":args,"request_id":requestID],token:token)
            if name=="android_device",["status","take","release","stop","trust"].contains(args["operation"] as? String ?? "") { lastState=result }
            return result
        }
        let command:[String:Any] = ["credential":agent ? access.agent_bootstrap:access.viewer_bootstrap,"name":name,"arguments":args,"request_id":requestID]
        let box=try ZeusLabEnvelope.seal(JSONSerialization.data(withJSONObject:command),to:access.control_public_key,session:saved.session)
        saved.sequence+=1;saved.pendingRequest=requestID;receipt=saved;try save()
        let body:[String:Any] = ["session":saved.session.uuidString.lowercased(),"sequence":saved.sequence,"payload":try JSONSerialization.jsonObject(with:JSONEncoder().encode(box))]
        let content=String(decoding:try JSONSerialization.data(withJSONObject:body),as:UTF8.self)+"\n"
        _ = try await writeMailbox(path:"experiments/actions-lab/control.json",content:content,message:"Encrypted ZEUS Android control \(saved.sequence)")
        let until=Date().addingTimeInterval(100)
        while Date()<until {
            try await poll()
            if let observed=observations.removeValue(forKey:requestID) {
                guard let status=observed["http_status"] as? Int,let result=observed["result"] as? [String:Any] else { throw ZeusPatch.failure("نتيجة Android غير مكتملة") }
                guard status==200 else { throw ZeusPatch.failure(result["detail"] as? String ?? "فشل أمر Android HTTP \(status)") }
                if name=="android_device",["status","take","release","stop"].contains(args["operation"] as? String ?? "") || name=="__take" { lastState=result }
                return result
            }
            if completed { break }
            try await Task.sleep(for:.seconds(3))
        }
        throw ZeusPatch.failure("انتهت مهلة انتظار النتيجة. قد يكون الأمر نُفذ؛ افحص الشاشة والسجلات قبل تكراره")
    }
    private func directRequest(path:String,body:[String:Any],token:String) async throws -> [String:Any] {
        guard let access=connection,access.url.scheme=="https",access.url.host?.hasSuffix(".trycloudflare.com")==true else { throw ZeusPatch.failure("الاتصال المباشر غير متاح") }
        var components=URLComponents(url:access.url,resolvingAgainstBaseURL:false)!;components.path=path;components.fragment=nil;components.query=nil
        var request=URLRequest(url:components.url!);request.httpMethod="POST";request.timeoutInterval=20;request.httpBody=try JSONSerialization.data(withJSONObject:body)
        request.setValue("Bearer "+token,forHTTPHeaderField:"Authorization");request.setValue("application/json",forHTTPHeaderField:"Content-Type")
        let configuration=URLSessionConfiguration.ephemeral;configuration.urlCache=nil
        let transport=URLSession(configuration:configuration,delegate:ZeusLabNoRedirect(),delegateQueue:nil);defer { transport.invalidateAndCancel() }
        let data:Data,response:URLResponse
        do { (data,response)=try await transport.data(for:request) }
        catch { throw ZeusPatch.failure("انقطع الاتصال بعد إرسال الأمر؛ قد يكون نُفّذ. افحص الشاشة قبل تكراره، أو استعد التحكم عبر GitHub.") }
        guard data.count<=4*1024*1024,let object=try JSONSerialization.jsonObject(with:data) as? [String:Any] else { throw ZeusPatch.failure("النتيجة المباشرة غير مكتملة؛ افحص الشاشة قبل إعادة الأمر") }
        guard (response as? HTTPURLResponse)?.statusCode==200 else { throw ZeusPatch.failure(object["detail"] as? String ?? "فشل أمر المختبر المباشر") }
        return object
    }
}

private final class ZeusLabNoRedirect:NSObject,URLSessionTaskDelegate {
    func urlSession(_ session:URLSession,task:URLSessionTask,willPerformHTTPRedirection response:HTTPURLResponse,newRequest request:URLRequest,completionHandler:@escaping (URLRequest?)->Void) { completionHandler(nil) }
}

@MainActor extension ZeusActionsLab {
    func stop() async throws {
        let saved=try requireOwner()
        if connection != nil,!completed { if busy { _ = try await takeControl() };_ = try await queued("android_device",args:["operation":"stop"],requestID:UUID().uuidString.lowercased());phase="يجري حفظ النتائج وإنهاء الجلسة…" }
        else if let run=saved.runID {
            _ = try await client.request(accountID:saved.accountID,method:"POST",path:"/repos/"+saved.repository+"/actions/runs/\(run)/cancel")
            phase="طُلب إلغاء تجهيز المحاكي"
        }
    }
    func upload(_ source:URL) async throws -> ZeusAndroidAPKTransfer.Uploaded {
        let saved = try requireOwner()
        guard let connection,!completed,!busy else { throw ZeusPatch.failure("انتظر اتصال المحاكي وانتهاء الأمر السابق") }
        let scoped=source.startAccessingSecurityScopedResource();defer { if scoped { source.stopAccessingSecurityScopedResource() } }
        let values=try source.resourceValues(forKeys:[.isRegularFileKey,.fileSizeKey])
        guard values.isRegularFile==true,let bytes=values.fileSize,bytes>0,bytes<=256*1024*1024,source.pathExtension.lowercased()=="apk" else { throw ZeusPatch.failure("اختر APK أصغر من256 MiB") }
        if let release=saved.releaseID {
            let asset=try await uploadReleaseAPK(source,bytes:bytes,receipt:saved,release:release)
            let result=try await execute("__upload",args:asset)
            guard let identifier=result["id"] as? String,UUID(uuidString:identifier) != nil,let sha=result["sha256"] as? String,sha==asset["sha256"] as? String else { throw ZeusPatch.failure("لم تتطابق نتيجة استيراد APK من GitHub") }
            return .init(project:identifier,sha256:sha)
        }
        guard connection.url.scheme=="https",connection.url.host?.hasSuffix(".trycloudflare.com")==true else { throw ZeusPatch.failure("رابط رفع الجلسة غير متاح؛ لم ينسخ الملف إلى بيئة محلية") }
        busy=true;defer { busy=false }
        let configuration=URLSessionConfiguration.ephemeral;configuration.urlCache=nil;configuration.requestCachePolicy = .reloadIgnoringLocalCacheData;configuration.timeoutIntervalForRequest=180;configuration.timeoutIntervalForResource=300
        let transport=URLSession(configuration:configuration,delegate:ZeusLabNoRedirect(),delegateQueue:nil);defer { transport.invalidateAndCancel() }
        var components=URLComponents(url:connection.url,resolvingAgainstBaseURL:false)!;components.fragment=nil;components.query=nil;components.path="/v1/access/renew"
        var renew=URLRequest(url:components.url!);renew.httpMethod="POST";renew.setValue("Bearer "+connection.viewer_bootstrap,forHTTPHeaderField:"Authorization")
        let (raw,response)=try await transport.data(for:renew)
        guard (response as? HTTPURLResponse)?.statusCode==200,let access=try JSONSerialization.jsonObject(with:raw) as? [String:Any],let token=access["token"] as? String else { throw ZeusPatch.failure("تعذر الوصول إلى رابط رفع APK المؤقت. التحكم عبر GitHub يظل منفصلًا؛ لم يُرفع الملف") }
        components.path="/v1/upload";var request=URLRequest(url:components.url!);request.httpMethod="POST";request.setValue("Bearer "+token,forHTTPHeaderField:"Authorization");request.setValue("application/vnd.android.package-archive",forHTTPHeaderField:"Content-Type");request.setValue(source.lastPathComponent.addingPercentEncoding(withAllowedCharacters:.urlPathAllowed),forHTTPHeaderField:"X-Filename")
        let (result,uploaded)=try await transport.upload(for:request,fromFile:source)
        guard (uploaded as? HTTPURLResponse)?.statusCode==200,let project=try JSONSerialization.jsonObject(with:result) as? [String:Any],let id=project["id"] as? String,UUID(uuidString:id) != nil,let sha=project["sha256"] as? String,sha.count==64 else { throw ZeusPatch.failure("رفع APK لم يتأكد؛ افحص قائمة المشاريع قبل تكراره") }
        return .init(project:id,sha256:sha)
    }
    private func uploadReleaseAPK(_ source:URL,bytes:Int,receipt saved:Receipt,release:Int) async throws -> [String:Any] {
        let repo=try await client.object(accountID:saved.accountID,path:"/repos/"+saved.repository)
        let metadata=try await client.object(accountID:saved.accountID,path:"/repos/"+saved.repository+"/releases/\(release)")
        guard repo["private"] as? Bool==true,metadata["tag_name"] as? String=="zeus-lab-"+saved.session.uuidString.lowercased(),metadata["draft"] as? Bool==true else { throw ZeusPatch.failure("أرشيف APK يجب أن يخص هذه الجلسة في المستودع الخاص") }
        let input=try FileHandle(forReadingFrom:source);defer { try? input.close() }
        var hash=SHA256();var count=0
        while let block=try input.read(upToCount:256*1024),!block.isEmpty { hash.update(data:block);count+=block.count;try Task.checkCancellation();await Task.yield() }
        guard count==bytes else { throw ZeusPatch.failure("تغير APK أثناء قراءته؛ أعد اختياره") }
        let digest=hash.finalize().map { String(format:"%02x",$0) }.joined()
        let assetName="apk-"+UUID().uuidString.lowercased()+".apk"
        var components=URLComponents(string:"https://uploads.github.com/repos/"+saved.repository+"/releases/\(release)/assets")!
        components.queryItems=[URLQueryItem(name:"name",value:assetName)]
        var request=URLRequest(url:components.url!);request.httpMethod="POST";request.timeoutInterval=300
        request.setValue("Bearer "+(try await ZeusConnections.shared.githubAccessToken(saved.accountID)),forHTTPHeaderField:"Authorization")
        request.setValue("application/vnd.android.package-archive",forHTTPHeaderField:"Content-Type");request.setValue(String(bytes),forHTTPHeaderField:"Content-Length");request.setValue("ZEUS-Browser",forHTTPHeaderField:"User-Agent")
        let configuration=URLSessionConfiguration.ephemeral;configuration.urlCache=nil;configuration.timeoutIntervalForResource=360
        let transport=URLSession(configuration:configuration,delegate:ZeusLabNoRedirect(),delegateQueue:nil);defer { transport.invalidateAndCancel() }
        let (raw,response)=try await transport.upload(for:request,fromFile:source)
        guard (response as? HTTPURLResponse)?.statusCode==201,let value=try JSONSerialization.jsonObject(with:raw) as? [String:Any],let identifier=value["id"] as? Int,value["size"] as? Int==bytes else { throw ZeusPatch.failure("لم يتأكد رفع APK إلى أرشيف GitHub؛ افحص الأصول قبل إعادة الرفع") }
        if let remote=value["digest"] as? String,remote != "sha256:"+digest { throw ZeusPatch.failure("بصمة APK على GitHub لا تطابق الأصل") }
        return ["url":try await signedAsset(identifier,receipt:saved),"sha256":digest,"filename":source.lastPathComponent]
    }
    private func signedAsset(_ identifier:Int,receipt saved:Receipt) async throws -> String {
        var request=URLRequest(url:URL(string:"https://api.github.com/repos/"+saved.repository+"/releases/assets/\(identifier)")!)
        request.setValue("Bearer "+(try await ZeusConnections.shared.githubAccessToken(saved.accountID)),forHTTPHeaderField:"Authorization");request.setValue("application/octet-stream",forHTTPHeaderField:"Accept");request.setValue("ZEUS-Browser",forHTTPHeaderField:"User-Agent")
        let transport=URLSession(configuration:.ephemeral,delegate:ZeusLabNoRedirect(),delegateQueue:nil);defer { transport.invalidateAndCancel() }
        let (_,response)=try await transport.bytes(for:request)
        guard let http=response as? HTTPURLResponse,(300..<400).contains(http.statusCode),let location=http.value(forHTTPHeaderField:"Location"),let url=URL(string:location),url.scheme=="https",["release-assets.githubusercontent.com","objects.githubusercontent.com"].contains(url.host ?? ""),url.user==nil,url.password==nil else { throw ZeusPatch.failure("تعذر إنشاء رابط تنزيل مؤقت لأصل GitHub الخاص") }
        return location
    }
    func refreshSavedProjects() async throws {
        let saved=try requireOwner()
        let result=try await client.request(accountID:saved.accountID,path:"/repos/"+saved.repository+"/releases",query:["per_page":"100"])
        let releases=result["data"] as? [[String:Any]] ?? []
        var values:[SavedProject]=[]
        for release in releases {
            guard release["draft"] as? Bool==true,let id=release["id"] as? Int,
                  (release["tag_name"] as? String)?.hasPrefix("zeus-lab-")==true,
                  let body=release["body"] as? String,body.contains(saved.owner),body.contains(conversation.uuidString.lowercased()) else { continue }
            let assets=(release["assets"] as? [[String:Any]] ?? []).filter { ($0["name"] as? String)?.hasSuffix(".tar.gz")==true }.sorted { ($0["name"] as? String ?? "") > ($1["name"] as? String ?? "") }
            guard let asset=assets.first,let assetID=asset["id"] as? Int,let bytes=asset["size"] as? Int,bytes>0,bytes<=1024*1024*1024,
                  let digest=asset["digest"] as? String,digest.hasPrefix("sha256:"),digest.count==71 else { continue }
            values.append(.init(id:id,title:release["created_at"] as? String ?? "جلسة محفوظة",assetID:assetID,bytes:bytes,sha256:String(digest.dropFirst(7)),final:asset["name"] as? String=="checkpoint-000099.tar.gz"))
        }
        savedProjects=values
    }
    func restore(_ project:SavedProject) async throws {
        let saved=try requireOwner()
        guard connection != nil,!completed else { throw ZeusPatch.failure("ابدأ جلسة Android جديدة لاستعادة المشروع إليها") }
        let url=try await signedAsset(project.assetID,receipt:saved)
        let result=try await execute("__restore",args:["url":url,"sha256":project.sha256])
        guard result["restored"] as? Bool==true else { throw ZeusPatch.failure("لم تتأكد استعادة المشروع") }
        phase="استُعيدت ملفات المشروع وتقاريره إلى الجلسة"
    }
    func exportReport(project:String,format:String,variant:String) async throws -> Data {
        guard UUID(uuidString:project) != nil,["json","html","pdf"].contains(format),["original","rebuilt"].contains(variant) else { throw ZeusPatch.failure("تقرير غير صالح") }
        let result=try await execute("__export",args:["project":project,"format":format,"variant":variant])
        guard let text=result["content"] as? String,text.utf8.count<=2_800_000,let data=Data(base64Encoded:text),data.count<=2*1024*1024,
              result["sha256"] as? String==SHA256.hash(data:data).map({String(format:"%02x",$0)}).joined() else { throw ZeusPatch.failure("لم تتطابق بصمة التقرير المُصدَّر") }
        return data
    }
    func route(_ path:String,body:[String:Any]?) async throws -> [String:Any] {
        guard path.hasPrefix("/v1/"),let url=URLComponents(string:path),url.host==nil else { throw ZeusPatch.failure("طلب واجهة غير مسموح") }
        switch url.path {
        case "/v1/transport":if let stream { return stream };return ["preferred":"github_frames","network_feed":"github_poll"]
        case "/v1/heartbeat":
            if Date().timeIntervalSince(lastHeartbeat)>45,!busy { _ = try await execute("__heartbeat",args:[:]);lastHeartbeat=Date() }
            return ["deadline":connection?.deadline ?? 0]
        case "/v1/session":
            if let cached=lastState { return cached }
            return try await queued("android_device",args:["operation":"status"],requestID:UUID().uuidString.lowercased())
        case "/v1/control/take":return try await takeControl()
        case "/v1/timeline":return try await execute("android_device",args:["operation":"timeline","after":Int(url.queryItems?.first(where:{$0.name=="after"})?.value ?? "0") ?? 0])
        case "/v1/tool":
            guard let body,let name=body["name"] as? String,ZeusAndroidTools.names.contains(name),let arguments=body["arguments"] as? [String:Any],let request=body["request_id"] as? String else { throw ZeusPatch.failure("أمر Android غير صالح") }
            return try await queued(name,args:arguments,requestID:request)
        case "/v1/upload":throw ZeusPatch.failure("ارفع APK باستخدام زر الرفع في شريط المختبر")
        default:throw ZeusPatch.failure("هذا المسار غير متاح عبر قناة GitHub")
        }
    }
    private func queued(_ name:String,args:[String:Any],requestID:String) async throws -> [String:Any] {
        guard pendingCount<12 else { throw ZeusPatch.failure("انتظر اكتمال الأوامر السابقة") }
        pendingCount+=1;defer { pendingCount-=1 }
        let previous=requestTail
        let result=Task { @MainActor in
            _ = await previous?.value
            try Task.checkCancellation()
            let deadline=Date().addingTimeInterval(30)
            while self.busy && Date()<deadline { try await Task.sleep(for:.milliseconds(200)) }
            return try await self.execute(name,args:args,requestID:requestID)
        }
        requestTail=Task { _ = await result.result }
        return try await result.value
    }
}

@MainActor extension ZeusActionsLab {
    private func writeMailbox(path:String,content:String,message:String) async throws -> [String:Any] {
        let saved=try requireOwner(),previous=writeTail
        let operation=Task { @MainActor in
            _ = await previous?.value
            return try await self.client.writeSources(accountID:saved.accountID,repository:saved.repository,branch:saved.branch,message:message,files:[["path":path,"content":content]])
        }
        writeTail=Task { _ = await operation.result }
        return try await operation.value
    }
    func takeControl() async throws -> [String:Any] {
        let saved=try requireOwner()
        guard let access=connection,!completed,access.deadline>Date().timeIntervalSince1970 else { throw ZeusPatch.failure("الجلسة غير متصلة أو انتهت") }
        guard !takingControl else { throw ZeusPatch.failure("استعادة التحكم قيد التنفيذ") }
        takingControl=true;defer { takingControl=false }
        if let token=stream?["stream_token"],let result=try? await directRequest(path:"/v1/control/take",body:[:],token:token) { lastState=result;return result }
        let request=UUID().uuidString.lowercased()
        let command:[String:Any] = ["name":"__take","request_id":request,"credential":access.viewer_bootstrap]
        let box=try ZeusLabEnvelope.seal(JSONSerialization.data(withJSONObject:command),to:access.control_public_key,session:saved.session)
        let packet:[String:Any] = ["session":saved.session.uuidString.lowercased(),"payload":try JSONSerialization.jsonObject(with:JSONEncoder().encode(box))]
        let content=String(decoding:try JSONSerialization.data(withJSONObject:packet),as:UTF8.self)+"\n"
        _ = try await writeMailbox(path:"experiments/actions-lab/emergency.json",content:content,message:"Reclaim Android control independently of the active tool")
        let deadline=Date().addingTimeInterval(45)
        while Date()<deadline {
            try await poll()
            if let value=emergencyResponses.removeValue(forKey:request),let status=value["http_status"] as? Int,let result=value["result"] as? [String:Any] {
                guard status==200 else { throw ZeusPatch.failure(result["detail"] as? String ?? "تعذر تأكيد استعادة التحكم") }
                lastState=result;return result
            }
            if completed { break }
            try await Task.sleep(for:.seconds(1))
        }
        throw ZeusPatch.failure("لم يتأكد إيقاف أداة Android بعد؛ يمكنك إنهاء تشغيل الجلسة من GitHub")
    }
}
