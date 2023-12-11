import axios from "axios";
import { useRef, useState } from "react";
import { emojiList } from "./emojis";
import styles from '../detail.module.css'

function AddReComment(props) {
    const { index, toggleReply, commentList, getCommentList } = props;
    const textAreaRef = useRef();
    const [comment, setComment] = useState('');



    const loginCheck = (member_id) => {
        if (member_id === null) { window.alert("로그인해주세요!"); return; };

    }

    const insertReComment = async () => {
        const member_id = sessionStorage.getItem("MEMBER_ID");
        const reply = textAreaRef.current.value;

        loginCheck(member_id);

        if (reply.length < 3) {
            window.alert("네글자이상 입력해주세요!!")
        } else {
            await axios.post('/board/insertReReply', {
                member_id: member_id,
                board_id: commentList.board_id,
                b_reply: reply,
                ref: commentList.ref,
                seq: commentList.seq
            }).then(() => {
                getCommentList()
                toggleReply(index)
            }).catch(error => {
            })
        }

    };

    const emo = (event, emoji) => {
        event.preventDefault();
        const textarea = document.getElementById("re_comment");
        const startPos = textarea.selectionStart;
        const endPos = textarea.selectionEnd;
        const value = textarea.value;
        const newValue =
            value.substring(0, startPos) +
            emoji +
            value.substring(endPos, value.length);
        setComment(newValue);
        textarea.focus();
        textarea.setSelectionRange(startPos + emoji.length, startPos + emoji.length);
    }

    const limitComment = (event) => {
        const value = event.target.value;
        if (value.length <= 200) {
            setComment(value);

        }
    }

    return (
        <>
            <td style={{ width: '20%', textAlign: 'center' }}>hong1</td>
            <td style={{ width: '40%' }} colSpan={4}>
                <textarea
                    ref={textAreaRef}
                    className={styles.re_comment}
                    id="re_comment"
                    value={comment}
                    onChange={limitComment}
                    style={{
                        width: '80%',
                        height: 'auto',
                        minHeight: 100,
                        paddingTop: 10,
                        paddingBottom: 0,
                        paddingLeft: 10,
                    }}
                    rows={4}
                ></textarea>
                <div className={styles.emoticons} id="emoticons">
                    이모티콘:
                    {emojiList.map((emojiData, index) => (
                        <img
                            key={index}
                            onClick={(event) => emo(event, emojiData.emoji)}
                            src={emojiData.src}
                            alt={emojiData.alt}
                            title={emojiData.title}
                        />
                    ))}
                    <div className={styles.comment_cnt} id="comment_cnt">({comment.length} / 200)</div>
                </div>

                <div style={{ float: 'right', width: '40%' }}>
                    <button className="btn btn-white" id="reComment_create" onClick={insertReComment}>
                        댓글달기
                    </button>
                    <button className="btn btn-white" id="comment_update_cancle" onClick={() => toggleReply(index)}>
                        취소
                    </button>
                </div>
                <div style={{ clear: 'both', margin: '0 0 30px 0' }} />
            </td>
        </>
    );
}


export default AddReComment;