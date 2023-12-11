import axios from 'axios';
import React, { useState } from 'react';
import styles from '../updateBoard.module.css'
function ImageUpload(
  { member_id, setSelectedFiles, selectedFiles, originBoardImg, setOriginBoardImg, setImageCheck }
) {

  const handleFileSelect = (e) => {
    const files = e.target.files;
    const filesArr = Array
      .prototype
      .slice
      .call(files);

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


  const renderOriginBoardImg = () => {
    return originBoardImg.map((image) => (

      <a
        onClick={() => deleteBoardImg(image.boardimg_num)}
        id={`img_id_${image.board_id}`}
      >

        <img
          src={image.boardimg}
          className='selProductFile'
          title='Click to remove'
          alt='board'
        />
      </a>
    ));
  };

  const deleteBoardImg = async (boardimgNum) => {
    const result = window.confirm('사진을 삭제하시겠습니까?');
    const boardimg_num = boardimgNum;

    if (result) {
      try {
        await axios.delete(`/board/deleteBoardImg`, {
          params: {
            boardimg_num: boardimg_num
          }
        });
        // 통신이 성공하면 여기에서 이미지 갱신 로직을 구현하세요.
        // 임시 이미지 배열에서 해당 이미지를 제거하거나 다른 로직을 사용할 수 있습니다.
        setOriginBoardImg(originBoardImg.filter((img) => img.boardimgNum !== boardimgNum));
        setImageCheck(boardimgNum);
      } catch (error) {
      }
    }
  };


  return (
    <form onSubmit={handleSubmit}>
      <div id="boardImgOrigin" className={`${styles.boardImgOrigin} boardImgOrigin`}>
        <h2>본문 이미지</h2>
        <div className={`${styles.image_wrap} image_wrap`}>
          {renderOriginBoardImg()}
        </div>
        <div className={`${styles.imgs_file} imgs_file`}>
          <h2>
            <b>이미지 미리보기</b>
          </h2>
          <div className={`${styles.input_wrap} input_wrap`}>
            <button
              type="button"
              onClick={() => document.getElementById('input_imgs').click()}
              className={`${styles.my_button} my_button`}
            >
              파일 업로드
            </button>
            <input
              type="file"
              name="file"
              id="input_imgs"
              multiple="multiple"
              onChange={handleFileSelect}
              style={{
                display: 'none',
              }}
            />
          </div>
        </div>

        <div>
          <div className={`${styles.imgs_wrap} imgs_wrap`}>
            {selectedFiles &&
              selectedFiles.map((file, index) => (
                <a onClick={() => handleDeleteFile(index)} key={index}>
                  <img
                    src={URL.createObjectURL(file)}
                    className={`${styles.selProductFile} selProductFile`}
                    title="Click to remove"
                  />
                </a>
              ))}
          </div>
        </div>

        <input type="hidden" name="member_id" value={member_id} />
      </div>
    </form>
  );
}

export default ImageUpload;