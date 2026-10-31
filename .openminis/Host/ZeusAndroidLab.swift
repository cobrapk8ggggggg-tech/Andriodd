import SwiftUI
import WebKit
import ZEUSBrowser

enum ZeusAndroidAPKTransfer {
    struct Uploaded { let project:String;let sha256:String }
    @MainActor static func upload(source:URL,conversation:UUID) async throws -> Uploaded {
        let actions=ZeusActionsLab.shared(conversation)
        if actions.receipt != nil,!actions.completed { return try await actions.upload(source) }
        let scoped=source.startAccessingSecurityScopedResource()
        defer { if scoped { source.stopAccessingSecurityScopedResource() } }
        let values=try source.resourceValues(forKeys:[.fileSizeKey,.isRegularFileKey])
        guard values.isRegularFile == true,let size=values.fileSize,size>0,size<=256*1024*1024 else { throw ZeusPatch.failure("اختر ملف APK لا يتجاوز256 MiB") }
        let data=try await NativeCloudAccountAPI.runtime("v1/android/\(conversation.uuidString.lowercased())/access",method:"POST",body:Data("{}".utf8))
        let access=try JSONDecoder().decode(ZeusAndroidAccess.self,from:data)
        guard access.url.scheme=="https",access.url.user==nil,access.url.password==nil,
              var components=URLComponents(url:access.url,resolvingAgainstBaseURL:false) else { throw ZeusPatch.failure("عنوان المختبر غير صالح") }
        components.path="/v1/upload";components.query=nil;components.fragment=nil
        guard let url=components.url else { throw ZeusPatch.failure("عنوان رفع غير صالح") }
        var request=URLRequest(url:url);request.httpMethod="POST"
        request.setValue("Bearer "+access.token,forHTTPHeaderField:"Authorization")
        request.setValue("application/vnd.android.package-archive",forHTTPHeaderField:"Content-Type")
        request.setValue(source.lastPathComponent.addingPercentEncoding(withAllowedCharacters:.urlPathAllowed),forHTTPHeaderField:"X-Filename")
        let configuration=URLSessionConfiguration.ephemeral;configuration.urlCache=nil;configuration.httpMaximumConnectionsPerHost=1
        configuration.timeoutIntervalForRequest=180;configuration.timeoutIntervalForResource=300
        let session=URLSession(configuration:configuration);defer { session.invalidateAndCancel() }
        // Upload streams the picked file; no Data(contentsOf:) or persistent copy.
        let (responseData,response)=try await session.upload(for:request,fromFile:source)
        guard (response as? HTTPURLResponse)?.statusCode==200 else { throw ZeusPatch.failure("لم يكتمل رفع APK إلى المختبر؛ تحقق من الاتصال والحصة") }
        guard let value=try JSONSerialization.jsonObject(with:responseData) as? [String:Any],let project=value["id"] as? String,UUID(uuidString:project) != nil,
              let sha=value["sha256"] as? String,sha.count==64 else { throw ZeusPatch.failure("استجابة رفع APK غير مكتملة") }
        return Uploaded(project:project,sha256:sha)
    }
}

/// This feature has no RootfsManager/ISH dependency and never stages an APK in
/// the local agent workspace. The remote page uses a nonpersistent WebKit store.
enum ZeusAndroidTools {
    static let names: Set<String> = ["android_lab", "android_device", "android_ui", "android_screenshot", "android_network", "android_project"]
    static func schema(_ name: String) -> [String: Any]? {
        guard names.contains(name) else { return nil }
        var fields: [String: Any] = ["tool_title": ["type":"string"], "approval_reason":["type":"string"]]
        let operations: [String]
        switch name {
        case "android_lab": operations = ["start", "status", "stop"]
        case "android_device": operations = ["status", "stop", "capabilities", "timeline", "logs", "records", "record_start", "record_stop"]
        case "android_ui": operations = ["tree", "tap", "swipe", "type", "key", "launch"]
        case "android_network": operations = ["start", "stop", "list", "read", "coverage"]
        case "android_project": operations = ["list", "install", "analyze", "decode", "build", "job", "files", "read", "write", "audit", "report", "search", "compare"]
        default: operations = []
        }
        if !operations.isEmpty { fields["operation"] = ["type":"string", "enum":operations] }
        if name == "android_lab" { for field in ["account_id","repository","ref"] { fields[field] = ["type":"string", "maxLength":200] } }
        if name == "android_ui" {
            for field in ["x", "y", "x2", "y2"] { fields[field] = ["type":"number", "minimum":0, "maximum":1] }
            fields["text"] = ["type":"string", "maxLength":4000]
            fields["key"] = ["type":"string", "enum":["back", "home", "recent", "enter", "delete"]]
            fields["package"] = ["type":"string", "maxLength":200]
        }
        if name == "android_network" || name == "android_device" { fields["after"] = ["type":"integer", "minimum":0] }
        if name == "android_device" {
            fields["project"] = ["type":"string", "maxLength":36]
            fields["package"] = ["type":"string", "maxLength":200]
            fields["kind"] = ["type":"string", "enum":["logcat", "pcap", "video"]]
        }
        if name == "android_project" {
            fields["replace_existing"] = ["type":"boolean"]
            for field in ["project", "job", "path", "expected_sha256", "query", "section"] { fields[field] = ["type":"string", "maxLength":500] }
            fields["offset"] = ["type":"integer", "minimum":0]
            fields["content"] = ["type":"string", "maxLength":100000]
            fields["variant"] = ["type":"string", "enum":["original", "rebuilt"]]
            fields["tree"] = ["type":"string", "enum":["decoded", "sources"]]
        }
        return ["type":"object", "properties":fields, "required":operations.isEmpty ? [] : ["operation"], "additionalProperties":false]
    }
    @MainActor static var definitions: [AgentToolDefinition] {
        guard NativeCloudAccountAPI.ownerID != nil else { return [] }
        let descriptions = [
            "android_lab":"Start/status/stop this conversation's temporary GitHub Actions Android laboratory. For start supply the exact linked GitHub account_id, repository (owner/name), and source ref containing ZEUS Lab workflow. Private repositories are supported and use the account's Actions quota. Standard Ubuntu runner only, no paid hosting. Start returns a launch receipt, not proof Android booted: poll status until connected. Uploaded APKs, analysis and ADB run on Actions, never local Linux. Device can reconnect later; the current cloud-agent GitHub bridge needs ZEUS open while issuing commands. User can trust the session once and revoke it at any moment.",
            "android_device":"Remote Android status/capabilities/timeline, logs (optional package), project evidence records, record_start(kind logcat/pcap/video, project), record_stop or stop the device. Recordings are server-side, bounded to 180s/32MiB. PCAP requires tcpdump and does not decrypt TLS. The user must start Android and hand control to you; never infer availability or install an emulator locally. Human takeover interrupts actions and revokes modification consent.",
            "android_ui":"Inspect the remote Android UI or tap/swipe/type/launch. Coordinates are normalized 0...1. Read the UI tree first; screenshot for visual inspection. Human takeover blocks agent mutations. Text uses the laboratory's Unicode IME.",
            "android_screenshot":"Read the current remote Android screenshot using native image input. No screenshot is written to the iPhone or local Linux workspace.",
            "android_network":"Start/stop bounded HTTP(S) capture or read/list events. after is a numeric cursor. HTTPS requires a trusted certificate; pinned/non-proxy traffic may be unavailable. Never claim every request was captured or infer causality from timing alone.",
            "android_project":"Remote APK projects. audit runs signature verification, Apktool and JADX and creates an evidence-based report; poll job. report returns summary or a section (inventory/findings/dex/native_libraries/source_observations/coverage); offset pages findings. search uses a literal query in decoded/sources files. compare compares audited original/rebuilt variants. Static work does not start Android. decode/edit/build preserve the original; installing rebuilt with replace_existing:true explicitly permits resetting that app's emulator data when its signing key differs; write needs expected_sha256. Heuristics are observations, not confirmed vulnerabilities. Never build on Railway."
        ]
        return names.sorted().map { name in
            let shape = schema(name)!, properties = shape["properties"] as! [String:[String:Any]]
            let parameters = properties.mapValues { property in
                AgentToolParam(type: property["type"] as? String == "integer" ? .integer : .string,
                    description:"Use the structured JSON schema. " + (property["description"] as? String ?? ""))
            }
            return AgentToolDefinition(name:name, description:descriptions[name]!, parameters:parameters, required:shape["required"] as? [String] ?? [])
        }
    }
    @MainActor static func execute(_ name: String, args: [String:Any], session: String?, callID: String) async throws -> [String:Any] {
        guard let session, let identifier = UUID(uuidString:session), names.contains(name) else { throw ZeusPatch.failure("افتح محادثة محفوظة أولًا.") }
        let actions=ZeusActionsLab.shared(identifier)
        if name=="android_lab" {
            switch args["operation"] as? String {
            case "start":
                guard let account=args["account_id"] as? String,let repository=args["repository"] as? String,let ref=args["ref"] as? String else { throw ZeusPatch.failure("حدد حساب GitHub والمستودع وفرع مصدر المختبر") }
                try await actions.start(accountID:account,repository:repository,ref:ref)
            case "stop":try await actions.stop()
            case "status":if actions.receipt != nil { try await actions.poll() }
            default:throw ZeusPatch.failure("أمر جلسة غير صالح")
            }
            return ["phase":actions.phase,"connected":actions.connection != nil && !actions.completed,"completed":actions.completed,"run_id":actions.receipt?.runID as Any? ?? NSNull(),"repository":actions.receipt?.repository as Any? ?? NSNull(),"branch":actions.receipt?.branch as Any? ?? NSNull(),"execution":"github_actions","agent_bridge_requires_device":true]
        }
        if actions.receipt != nil,!actions.completed { return try await actions.execute(name,args:args,requestID:callID,agent:true) }
        let body: [String:Any] = ["name":name, "arguments":args, "request_id":callID]
        let data = try await NativeCloudAccountAPI.runtime("v1/android/\(identifier.uuidString.lowercased())/tool", method:"POST", body:JSONSerialization.data(withJSONObject:body))
        guard let value = try JSONSerialization.jsonObject(with:data) as? [String:Any] else { throw ZeusPatch.failure("استجابة مختبر غير صالحة.") }
        return value
    }
}

struct ZeusAndroidLabButton: View {
    let session: String?
    @State private var presented = false
    var body: some View {
        Button { presented = true } label: { Label("مختبر Android", systemImage:"apps.iphone") }
            .accessibilityIdentifier("zeusAndroidLabButton")
            .fullScreenCover(isPresented:$presented) { ZeusAndroidLabView(session:session) }
    }
}

struct ZeusAndroidLabView: View {
    let session:String?
    var chatPanel:AnyView? = nil
    var stopAgent:(() -> Void)? = nil
    @Environment(\.dismiss) private var dismiss
    var body:some View {
        NavigationStack {
            Group {
                if let session,let conversation=UUID(uuidString:session) { ZeusActionsLabView(conversation:conversation,chatPanel:chatPanel,stopAgent:stopAgent) }
                else { ContentUnavailableView("افتح محادثة محفوظة",systemImage:"bubble.left",description:Text("ترتبط جلسة المختبر بالمحادثة وحساب ZEUS.")) }
            }.navigationTitle("ZEUS · Android Lab").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement:.confirmationAction) { Button("إغلاق") { dismiss() } } }
        }.preferredColorScheme(.dark)
    }
}

struct ZeusHostedAndroidLabView: View {
    let session: String?
    var chatPanel: AnyView? = nil
    var stopAgent: (() -> Void)? = nil
    @Environment(\.dismiss) private var dismiss
    @State private var access: ZeusAndroidAccess?
    @State private var issue: String?
    @State private var loading = true
    @State private var showAgent = UIDevice.current.userInterfaceIdiom == .pad
    var body: some View {
        NavigationStack {
            Group {
                if let access {
                    GeometryReader { geometry in
                        HStack(spacing:0) {
                            if geometry.size.width >= 1000 || !showAgent || chatPanel == nil {
                                ZeusAndroidWebView(access:access, renew:load, stopAgent:stopAgent)
                            }
                            if showAgent, let chatPanel {
                                if geometry.size.width >= 1000 { Divider() }
                                VStack(spacing:0) {
                                    HStack { Label("وكيل المختبر",systemImage:"sparkles"); Spacer()
                                        if stopAgent != nil { Button("إيقاف واستعادة التحكم",role:.destructive) { stopAgent?(); Task { await takeControl() } } }
                                    }.font(.subheadline).padding(14)
                                    chatPanel
                                }.frame(width:geometry.size.width >= 1000 ? min(420,geometry.size.width * 0.34) : nil)
                            }
                        }
                    }
                }
                else {
                    VStack(spacing:22) {
                        Image(systemName:"apps.iphone").font(.system(size:65, weight:.ultraLight)).foregroundStyle(.mint)
                        Text("مختبر Android").font(.largeTitle.bold())
                        Text(issue ?? "يجري التحقق من اتصال المختبر…").font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth:430)
                        if loading { ProgressView() }
                        else { Button("إعادة التحقق") { Task { await load() } }.buttonStyle(.borderedProminent).tint(.mint).foregroundStyle(.black) }
                        Text("تشغيل منفصل عن جهازك وبيئة الوكيل المحلية").font(.caption).foregroundStyle(.secondary)
                    }.padding(28).frame(maxWidth:.infinity,maxHeight:.infinity)
                        .background(LinearGradient(colors:[Color(red:0.04,green:0.09,blue:0.07),.black], startPoint:.topTrailing,endPoint:.bottomLeading))
                }
            }
            .navigationTitle("ZEUS · Android").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement:.confirmationAction) { Button("إغلاق") { dismiss() } }
                ToolbarItem(placement:.primaryAction) {
                    if chatPanel != nil { Button { showAgent.toggle() } label: { Label(showAgent ? "عرض المختبر" : "عرض الوكيل",systemImage:"sidebar.right") } }
                }
            }
            .task { await load() }
        }.preferredColorScheme(.dark)
    }
    @MainActor private func load() async {
        loading = true; defer { loading = false }
        guard NativeCloudAccountAPI.ownerID != nil else { issue="سجّل دخولك إلى حساب ZEUS أولًا."; return }
        guard let session, let identifier = UUID(uuidString:session) else { issue="افتح محادثة محفوظة لربط المشروع ونتائجه بها."; return }
        do {
            let capabilities = try await NativeCloudAccountAPI.runtime("v1/android/capabilities")
            let value = try JSONSerialization.jsonObject(with:capabilities) as? [String:Any]
            guard value?["configured"] as? Bool == true else { issue=value?["reason"] as? String ?? "لم يربط خادم Android بعد."; return }
            let data = try await NativeCloudAccountAPI.runtime("v1/android/\(identifier.uuidString.lowercased())/access",method:"POST",body:Data("{}".utf8))
            access = try JSONDecoder().decode(ZeusAndroidAccess.self,from:data); issue=nil
        } catch { issue=error.localizedDescription }
    }
    @MainActor private func takeControl() async {
        guard let session,let identifier=UUID(uuidString:session) else { return }
        do { _ = try await NativeCloudAccountAPI.runtime("v1/android/\(identifier.uuidString.lowercased())/take",method:"POST",body:Data("{}".utf8)) }
        catch { issue=error.localizedDescription }
    }
}

struct ZeusAndroidAccess: Decodable, Equatable { let url: URL; let token: String }

private struct ZeusAndroidWebView: UIViewRepresentable {
    let access: ZeusAndroidAccess
    let renew: @MainActor () async -> Void
    var stopAgent: (() -> Void)? = nil
    func makeCoordinator() -> Coordinator { Coordinator(renew:renew,stopAgent:stopAgent) }
    func makeUIView(context:Context) -> WKWebView {
        let configuration = WKWebViewConfiguration(); configuration.websiteDataStore = .nonPersistent(); configuration.allowsInlineMediaPlayback=true
        configuration.mediaTypesRequiringUserActionForPlayback = []
        configuration.userContentController.add(context.coordinator,name:"labRenew")
        configuration.userContentController.add(context.coordinator,name:"labFullscreen")
        configuration.userContentController.add(context.coordinator,name:"labStopAgent")
        configuration.userContentController.add(context.coordinator,name:"labExport")
        let view = WKWebView(frame:.zero,configuration:configuration)
        view.navigationDelegate=context.coordinator; view.isOpaque=false; view.backgroundColor = .black
        context.coordinator.view=view; context.coordinator.origin=access.url
        return view
    }
    func updateUIView(_ view:WKWebView,context:Context) {
        guard access.url.scheme == "https", access.url.user == nil, access.url.password == nil else { return }
        if context.coordinator.loaded == nil {
            var components = URLComponents(url:access.url,resolvingAgainstBaseURL:false)!
            components.fragment="token="+access.token
            if let url=components.url { view.load(URLRequest(url:url,cachePolicy:.reloadIgnoringLocalCacheData)); context.coordinator.loaded=access }
        } else if context.coordinator.loaded?.token != access.token {
            if let raw=try? JSONSerialization.data(withJSONObject:[access.token]),let literal=String(data:raw,encoding:.utf8) {
                view.evaluateJavaScript("window.zeusLabRenew(\(literal)[0])",completionHandler:nil); context.coordinator.loaded=access
            }
        }
    }
    static func dismantleUIView(_ view:WKWebView,coordinator:Coordinator) {
        view.navigationDelegate=nil
        view.stopLoading(); view.loadHTMLString("",baseURL:nil)
        view.configuration.userContentController.removeScriptMessageHandler(forName:"labRenew")
        view.configuration.userContentController.removeScriptMessageHandler(forName:"labFullscreen")
        view.configuration.userContentController.removeScriptMessageHandler(forName:"labStopAgent")
        view.configuration.userContentController.removeScriptMessageHandler(forName:"labExport")
    }
    final class Coordinator: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
        weak var view:WKWebView?
        var origin:URL?
        var loaded:ZeusAndroidAccess?
        let renew:@MainActor () async -> Void
        let stopAgent:(() -> Void)?
        init(renew:@escaping @MainActor () async -> Void,stopAgent:(() -> Void)?=nil) { self.renew=renew;self.stopAgent=stopAgent }
        func webView(_ webView:WKWebView,decidePolicyFor action:WKNavigationAction,decisionHandler:@escaping (WKNavigationActionPolicy)->Void) {
            guard let url=action.request.url, url.scheme=="https",url.host==origin?.host,url.port==origin?.port else { decisionHandler(.cancel);return }
            decisionHandler(.allow)
        }
        func userContentController(_ controller:WKUserContentController,didReceive message:WKScriptMessage) {
            guard message.frameInfo.isMainFrame,message.frameInfo.securityOrigin.host==origin?.host else { return }
            if message.name=="labRenew" { Task { @MainActor in await renew() } }
            if message.name=="labStopAgent" { stopAgent?() }
            if message.name=="labExport",let value=message.body as? [String:String],let project=value["project"],UUID(uuidString:project) != nil,
               let format=value["format"],["json","html","pdf"].contains(format),let variant=value["variant"],["original","rebuilt"].contains(variant) {
                Task { @MainActor in await shareReport(project:project,format:format,variant:variant) }
            }
            if message.name=="labExport",let value=message.body as? [String:String],value["kind"]=="evidence",
               let project=value["project"],UUID(uuidString:project) != nil,let recording=value["record"],UUID(uuidString:recording) != nil,
               let suffix=value["extension"],["pcap","h264","log"].contains(suffix) {
                Task { @MainActor in await shareEvidence(project:project,recording:recording,suffix:suffix) }
            }
            if message.name=="labFullscreen" { view?.evaluateJavaScript("document.getElementById('screen').scrollIntoView({block:'start'})",completionHandler:nil) }
        }
        @MainActor private func shareReport(project:String,format:String,variant:String) async {
            guard let origin else { return }
            var components=URLComponents(url:origin,resolvingAgainstBaseURL:false)!
            components.path="/v1/projects/\(project)/export";components.queryItems=[URLQueryItem(name:"format",value:format),URLQueryItem(name:"variant",value:variant)];components.fragment=nil
            guard let url=components.url else { return }
            await shareFile(url:url,name:"ZEUS-Security-Report.\(format)",maximum:8*1024*1024)
        }
        @MainActor private func shareEvidence(project:String,recording:String,suffix:String) async {
            guard let origin else { return }
            var components=URLComponents(url:origin,resolvingAgainstBaseURL:false)!
            components.path="/v1/projects/\(project)/evidence/\(recording)";components.query=nil;components.fragment=nil
            guard let url=components.url else { return }
            await shareFile(url:url,name:"ZEUS-Evidence.\(suffix)",maximum:40*1024*1024)
        }
        @MainActor private func shareFile(url:URL,name:String,maximum:Int) async {
            guard let loaded,let view else { return }
            var request=URLRequest(url:url);request.setValue("Bearer "+loaded.token,forHTTPHeaderField:"Authorization")
            let configuration=URLSessionConfiguration.ephemeral;configuration.urlCache=nil
            let session=URLSession(configuration:configuration);defer { session.invalidateAndCancel() }
            do {
                let (temporary,response)=try await session.download(for:request)
                defer { try? FileManager.default.removeItem(at:temporary) }
                guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw ZeusPatch.failure("تعذر تصدير التقرير") }
                let size=(try FileManager.default.attributesOfItem(atPath:temporary.path)[.size] as? NSNumber)?.intValue ?? Int.max
                guard size<=maximum else { throw ZeusPatch.failure("الملف يتجاوز حد المشاركة") }
                let directory=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString,isDirectory:true)
                try FileManager.default.createDirectory(at:directory,withIntermediateDirectories:true)
                let file=directory.appendingPathComponent(name);try FileManager.default.moveItem(at:temporary,to:file)
                let share=UIActivityViewController(activityItems:[file],applicationActivities:nil)
                share.completionWithItemsHandler={ _,_,_,_ in try? FileManager.default.removeItem(at:directory) }
                share.popoverPresentationController?.sourceView=view;share.popoverPresentationController?.sourceRect=CGRect(x:view.bounds.midX,y:60,width:1,height:1)
                var presenter=view.window?.rootViewController
                while let presented=presenter?.presentedViewController { presenter=presented }
                presenter?.present(share,animated:true)
            } catch {
                if let encoded=try? JSONSerialization.data(withJSONObject:[error.localizedDescription]),let literal=String(data:encoded,encoding:.utf8) {
                    view.evaluateJavaScript("window.zeusLabIssue(\(literal)[0])",completionHandler:nil)
                }
            }
        }
    }
}
