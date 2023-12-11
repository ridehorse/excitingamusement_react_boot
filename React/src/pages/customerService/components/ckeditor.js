import React from "react";
import { CKEditor } from "@ckeditor/ckeditor5-react";
import ClassicEditor from "@ckeditor/ckeditor5-build-classic";
import "./ckeditor.css";
const Ckeditor = ({ onImageUpload, ckeditorData, content }) => {
  const customUploadAdapter = (loader) => {
    return {
      upload() {
        return new Promise((resolve, reject) => {
          const formData = new FormData();
          loader.file.then((file) => {
            formData.append("file", file);

            onImageUpload(formData)
              .then((response) => {
                resolve({ default: response.data.url });
              })
              .catch((error) => {
                reject(error);
              });
          });
        });
      },
    };
  };

  function uploadPlugin(editor) {
    editor.plugins.get("FileRepository").createUploadAdapter = (loader) => {
      return customUploadAdapter(loader);
    };
  }

  ClassicEditor.defaultConfig = {
    ...ClassicEditor.defaultConfig,
    minHeight: "400px", // 원하는 높이로 설정
  };

  //참이면 글 생성 / 거짓이면 글 수정
  const dataToRender = content !== undefined ? `${content}` : "";

  return (
    <div className="Editor">
      <section>
        <CKEditor
          editor={ClassicEditor}
          data={dataToRender}
          config={{ extraPlugins: [uploadPlugin] }}
          onReady={(editor) => {
            // You can store the "editor" and use when it is needed.
            console.log("Editor is ready to use!", editor);
          }}
          onChange={(event, editor) => {
            const data = editor.getData();
            ckeditorData.current = data;
            console.log({ event, editor, ckeditorData, content });
          }}
          onBlur={(event, editor) => {
            console.log("Blur.", editor);
          }}
          onFocus={(event, editor) => {
            console.log("Focus.", editor);
          }}
        />
      </section>
    </div>
  );
};

export default Ckeditor;
