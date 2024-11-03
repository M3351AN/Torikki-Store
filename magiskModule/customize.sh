$BOOTMODE || abort "! Can not be installed in recovery. "

[ $ARCH == "arm64" ] || abort "! ONLY support ARM64"

#$KSU|| abort "! ONLY support KernelSU."

module_id="$(grep_prop id $MODPATH/module.prop)"
#module_name="$(grep_prop name $MODPATH/module.prop)"
#module_version="$(grep_prop version $MODPATH/module.prop)"

ui_print " "
ui_print "- KSUVersion=$KSU_VER"
ui_print "- KSUVersionCode=$KSU_VER_CODE"
ui_print "- KSUKernelVersionCode=$KSU_KERNEL_VER_CODE"

chmod a+x $MODPATH/$module_id

#$MODPATH/torikki-store

ui_print " "

ui_print "- Installed success."