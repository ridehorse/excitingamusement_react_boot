import React, { useState } from 'react';

function ImageUpload({ member_id, setSelectedFiles, selectedFiles }) {


  const handleFileSelect = (e) => {
    const files = e.target.files;
    const filesArr = Array.prototype.slice.call(files);

    // 이미지 파일만 선택
    const imageFiles = filesArr.filter((file) => file.type.match('image.*'));

    if (imageFiles.length === 0) {
      alert('이미지 파일만 업로드 가능합니다.');
      return;
    }

    setSelectedFiles(imageFiles);
  };

  const handleDeleteFile = (index) => {
    setSelectedFiles((prev) => prev.filter((_, i) => i !== index));
  };

  const handleSubmit = (e) => {
    e.preventDefault();

    // 이미지 파일 업로드 로직 구현
  };

  return (
    <form onSubmit={handleSubmit}>
      <div className="imgs_file">
        <h2>
          <b>이미지 미리보기</b>
        </h2>
        <div className="input_wrap">
          <button type="button" onClick={() => document.getElementById('input_imgs').click()} className="my_button">
            파일 업로드
          </button>
          <input type="file" name="file" id="input_imgs" multiple onChange={handleFileSelect} style={{ display: 'none' }} />
        </div>
      </div>

      <div>
        <div className="imgs_wrap">
          {selectedFiles.map((file, index) => (
            <a onClick={() => handleDeleteFile(index)} key={index}>
              <img src={URL.createObjectURL(file)} className="selProductFile" title="Click to remove" />
            </a>
          ))}
        </div>
      </div>

      <input type="hidden" name="member_id" value={member_id} />
    </form>
  );
}

export default ImageUpload;