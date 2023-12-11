import React from "react";
import "./Advertisement.css"; // 경로에 맞게 변경하세요.

const Advertisement = () => {
  return (
    <div className="aside-wrap" style={{ marginTop: 350 }}>
      <div className="aside-inner bottom-right top-left">
        <a href="http://jg.tjoeunit.co.kr/">
          <img
            id="advertisement1"
            alt=""
            src="https://tpc.googlesyndication.com/simgad/2289797006222971694?sqp=4sqPyQQ7QjkqNxABHQAAtEIgASgBMAk4A0DwkwlYAWBfcAKAAQGIAQGdAQAAgD-oAQGwAYCt4gS4AV_FAS2ynT4&rs=AOga4qnEJ0oNxtfLOFYaUuhbbHSr4SxPpw"
          />
        </a>
      </div>
    </div>
  );
};

export default Advertisement;
