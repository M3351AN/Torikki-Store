$BOOTMODE || abort "! ONLY can be installed on KernelSU. "

[ $ARCH == "arm64" ] || abort "! ONLY support ARM64"

$KSU|| abort "! ONLY support KernelSU."

module_id="$(grep_prop id $MODPATH/module.prop)"
#module_name="$(grep_prop name $MODPATH/module.prop)"
#module_version="$(grep_prop version $MODPATH/module.prop)"

ui_print " "
ui_print "- KSUVersion=$KSU_VER"
ui_print "- KSUVersionCode=$KSU_VER_CODE"
ui_print "- KSUKernelVersionCode=$KSU_KERNEL_VER_CODE"

ui_print "! If your App profile default setting is not UMOUNT, please change the value in default_umount.txt under module directory to 0 after reboot, and then execute the action to refresh"

chmod a+x $MODPATH/$module_id
chmod a+x $MODPATH/service.sh
chmod a+x $MODPATH/action.sh

#$MODPATH/torikki-store

ui_print " "

ui_print "- Installed success, please reboot."