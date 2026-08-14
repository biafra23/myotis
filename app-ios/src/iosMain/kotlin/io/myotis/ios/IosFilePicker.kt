package io.myotis.ios

import platform.Foundation.NSURL
import platform.UIKit.UIApplication
import platform.UIKit.UIDocumentPickerDelegateProtocol
import platform.UIKit.UIDocumentPickerViewController
import platform.UIKit.UIViewController
import platform.UniformTypeIdentifiers.UTTypeItem
import platform.darwin.NSObject

/**
 * The system document picker, presented from the Compose host's root view
 * controller — the seam behind [io.myotis.ui.NodeController.importLogIndexSnapshots]
 * on this host. `asCopy = true` makes UIKit hand back plain readable copies in
 * the app's tmp container, so no security-scoped-resource dance is needed and
 * the returned paths can go straight to the engine (which reads paths, not
 * streams). Must be called on the main thread (Compose click handlers are).
 */
internal object IosFilePicker {

    // UIKit holds its delegate weakly — keep the active one alive until the
    // picker resolves (picked or cancelled), one pick in flight at a time
    // (the picker is modal).
    private var active: PickerDelegate? = null

    fun pickFiles(onPicked: (List<String>) -> Unit) {
        val root = rootViewController() ?: run {
            onPicked(emptyList())
            return
        }
        val delegate = PickerDelegate { paths ->
            active = null
            onPicked(paths)
        }
        active = delegate
        val picker = UIDocumentPickerViewController(
            forOpeningContentTypes = listOf(UTTypeItem), // snapshots have no registered type
            asCopy = true,
        )
        picker.allowsMultipleSelection = true
        picker.delegate = delegate
        root.presentViewController(picker, animated = true, completion = null)
    }

    private fun rootViewController(): UIViewController? =
        UIApplication.sharedApplication.keyWindow?.rootViewController

    private class PickerDelegate(
        private val onDone: (List<String>) -> Unit,
    ) : NSObject(), UIDocumentPickerDelegateProtocol {

        override fun documentPicker(
            controller: UIDocumentPickerViewController,
            didPickDocumentsAtURLs: List<*>,
        ) {
            onDone(didPickDocumentsAtURLs.mapNotNull { (it as? NSURL)?.path })
        }

        override fun documentPickerWasCancelled(controller: UIDocumentPickerViewController) {
            onDone(emptyList())
        }
    }
}
