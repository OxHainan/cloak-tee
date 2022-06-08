#pragma once
#ifdef __cplusplus
extern "C"
{
#endif
    using export_state_func_t = bool (*)(uint256_t, uint256_t, uint256_t*);

    export_state_func_t export_state;
    bool register_export_state(export_state_func_t pf)
    {
        export_state = pf;
        return true;
    }
#ifdef __cplusplus
}
#endif