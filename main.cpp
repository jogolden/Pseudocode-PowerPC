// Originally created by Youness Alaoui
// Pseudo code generation by xemio (also known as golden)

#include "ida.hpp"
#include "engine.hpp"

struct pseudocode_info_t {
	TForm *form;
	TCustomControl *cv, *pcv;
	strvec_t sv;
	pseudocode_info_t(TForm *f) : form(f), cv(NULL), pcv(NULL) {}
};

int idaapi PluginStartup(void) {
	if(ph.id == PLFM_PPC) {
		return PLUGIN_OK;
	}
	return PLUGIN_SKIP;
}

void idaapi PluginShutdown(void) {

}

void idaapi PluginMain(int param) {
	TForm *PseudoCodeForm = find_tform("Pseudo Code");
	if(PseudoCodeForm != NULL) {
		close_tform(PseudoCodeForm, true);
		//switchto_tform(PseudoCodeForm, true);
		//return;
	}

	PseudoCodeForm = create_tform("Pseudo Code", NULL);
	pseudocode_info_t *si = new pseudocode_info_t(PseudoCodeForm);
	parse_current_function(&si->sv);
	simpleline_place_t s1, s2(si->sv.size() - 1);
	si->cv = create_custom_viewer("", (TWinControl *)PseudoCodeForm, &s1, &s2, &s1, 0, &si->sv);
	si->pcv = create_code_viewer(PseudoCodeForm, si->cv, CDVF_LINEICONS);
	set_code_viewer_lines_icon_margin(si->pcv, 0);
	open_tform(PseudoCodeForm, FORM_TAB | FORM_MENU | FORM_RESTORE | FORM_QWIDGET);
}

const char g_PluginComment[] = "PowerPC to C pseudo code";
const char g_PluginHelp[] = "This plugin converts a function in PowerPC into its relevant C pseudo code.\n";
const char g_PluginName[] = "PPC2C";
const char g_PluginHotKey[] = "F10";

plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION,
	NULL,
	PluginStartup,
	PluginShutdown,
	PluginMain,
	g_PluginComment,
	g_PluginHelp,
	g_PluginName,
	g_PluginHotKey
};
