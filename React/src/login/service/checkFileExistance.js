import React from "react";
import { call } from "./ApiService";

export function checkFileExistance(projectFolderPath,targetFileName, member_id) {
  // fs 모듈은 파일 시스템과npm 관련된 다양한 기능을 제공합니다.
  // 파일 읽기, 쓰기, 삭제, 폴더 생성 등의 파일 시스템 조작 작업을 수행할 때 사용됩니다
  // const fs = require('fs'); 
  // path 모듈은 파일 및 디렉터리 경로와 관련된 유틸리티 함수를 제공합니다.
  // 경로 연결, 디렉터리 이름 추출, 상대 경로를 절대 경로로 변환하는 등의 작업을 수행할 때 사용됩니다.
  // const path = require('path');

  const checkFileExistence = (folderPath, fileName) => {
  // const filePath = path.join(folderPath, fileName);

  try {
    // fs.accessSync를 사용하여 파일이나 폴더의 존재 여부를 확인
    // fs.accessSync(filePath, fs.constants.F_OK);
    console.log(`File ${fileName} exists in ${folderPath}`);
    return true;
  } catch (error) {
    console.log(`File ${fileName} does not exist in ${folderPath}`);
    
    const request = {
      member_id: member_id, 
    };

    call("/mypage/editMember", "GET", request).then((response) => {
      if (response === 1) {
        console.log("editmember 수정 성공");
        alert("정보수정이 성공적으로 완료되었습니다.");
        window.location.href = "/";
      } else {
        console.log("editmember 수정 실패");
      }
    });
    
    return false;
  }
  };
}


