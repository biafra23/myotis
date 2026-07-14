import SwiftUI
import MyotisKit

/// Thin SwiftUI shell: the whole app is the shared Compose UI, served by
/// MyotisKit's MainViewController() (the Kotlin composition root).
@main
struct MyotisApp: App {
    var body: some Scene {
        WindowGroup {
            ComposeView()
                .ignoresSafeArea(.keyboard) // Compose handles its own insets
        }
    }
}

struct ComposeView: UIViewControllerRepresentable {
    func makeUIViewController(context: Context) -> UIViewController {
        MainViewControllerKt.MainViewController()
    }

    func updateUIViewController(_ uiViewController: UIViewController, context: Context) {}
}
