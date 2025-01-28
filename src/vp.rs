use serde::{Deserialize, Serialize};
use serde_json::Value;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

#[derive(Serialize, Deserialize, Clone)]
#[wasm_bindgen]
pub struct VPData {
    #[wasm_bindgen(skip)]
    pub vp_token: Value,
    #[wasm_bindgen(skip)]
    pub _vp_token: Value,
}

#[wasm_bindgen]
impl VPData {
    #[wasm_bindgen(getter = vp_token)]
    pub fn vp_token(&self) -> JsValue {
        match serde_wasm_bindgen::to_value(&self.vp_token) {
            Ok(val) => val,
            Err(_) => JsValue::NULL,
        }
    }

    #[wasm_bindgen(setter = vp_token)]
    pub fn set_vp_token(&mut self, vp_token: JsValue) {
        match serde_wasm_bindgen::from_value(vp_token) {
            Ok(val) => self.vp_token = val,
            Err(_) => self.vp_token = Value::Null,
        };
    }
    #[wasm_bindgen(getter = _vp_token)]
    pub fn _vp_token(&self) -> JsValue {
        match serde_wasm_bindgen::to_value(&self._vp_token) {
            Ok(val) => val,
            Err(_) => JsValue::NULL,
        }
    }

    #[wasm_bindgen(setter = _vp_token)]
    pub fn set__vp_token(&mut self, _vp_token: JsValue) {
        match serde_wasm_bindgen::from_value(_vp_token) {
            Ok(val) => self._vp_token = val,
            Err(_) => self._vp_token = Value::Null,
        };
    }
}
