import React from "react";

export function openPopup(url) {
  const popupWindow = window.open(url, "_blank", "width=600,height=880");
  if (popupWindow) {
    popupWindow.focus();
  }
}
