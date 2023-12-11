import React, { useRef, useState } from "react";
import { CKEditor } from "@ckeditor/ckeditor5-react";
import ClassicEditor from "@ckeditor/ckeditor5-build-classic";


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
                    }}
                    onChange={(event, editor) => {
                        const data = editor.getData()
                        ckeditorData.current = data
                    }}
                    onBlur={(event, editor) => {
                    }}
                    onFocus={(event, editor) => {
                    }}
                />
            </section>

        </div>
    );
};

export default Ckeditor;