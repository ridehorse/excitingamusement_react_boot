// import React, { useEffect, useLayoutEffect, useState } from 'react';
// import './modal.scss';

// import io from 'socket.io-client';

// function ShowChatList(props){
//     return (
//     //내가 보낸 메세지
//     // props.user === props.member_id
//     // ?
//     // <div style={{float:'right'}}>
//     //     <ul>
//     //     {props.receivedMessages?.map((msg, index) => (
//     //         <li key={index} style={{textAlign:'right'}}>
//     //             {props.member_id} : {msg}
//     //         </li>
//     //     ))}
//     //     </ul>
//     // </div>
//     // :
//     // //상대방이 보낸 메세지
//     // <div style={{float:'left'}}>
//     //     <ul>
//     //     {props.receivedMessages.map((msg, index) => (
//     //         <li key={index} style={{textAlign:'left'}}>
//     //             {props.member_id} : {msg}
//     //         </li>
//     //     ))}
//     //     </ul>
//     // </div>
    
//     <div>
//         <ul>
//         {props.receivedMessages?.map((msg, index) => (
//             <li key={index} style={{textAlign:'right'}}>
//                 {props.member_id} : {msg}
//             </li>
//         ))}
//         </ul>
//     </div>
//     )
// }

// const ModalChat = (props) => {
//     const { open, close, header, member_id } = props;

//     const [message, setMessage] = useState('');
//     const [receivedMessages, setReceivedMessages] = useState([]);

//     // const [enterMsg, setEnterMsg] = useState([]);
//     // const [isOpen, setIsOpen] = useState(false);
    
//     // const [user, setUser] = useState(member_id);

//     const socket = io('http://localhost:5000', {
// 		cors: {
// 			origin: "*",
// 		}
// 	});
    
//     socket.on('test', data => {
//         setReceivedMessages((prevMessages) => [...prevMessages, data.message]);
//         // setUser(data.member_id);
//     });

// 	const sendMessage = e => {
//         e.preventDefault();
        
//         //소켓 서버로 데이터 전송
// 		socket.emit("test", {
// 			member_id: member_id, message: message
// 		});

//         setMessage("");
//         e.target.value = "";
// 	}

//     //===================================    
//     // useLayoutEffect(() => {
//     //     if (open) {
//     //       // 채팅창이 열리면 상태 초기화
//     //       setIsOpen(true);
//     //       setReceivedMessages([]);

//     //       socket.emit("enter", {
//     //         enterMsg : `${member_id}님이 입장했습니다`
//     //       });
//     //     }
//     //     else{
//     //         socket.disconnect();
//     //     }
//     //   },[open]);
//     //===================================
      

//     return (
//         <div className={open ? 'openModal modal' : 'modal'}>    
//             {open ? 
//             (
//             <section style={{position:'relative'}}>
//                 <header>
//                     <h4>{header}</h4>
//                     <button className="close" onClick={close}>
//                         X
//                     </button>
//                 </header>
//                 <main style={{position:'relative', height:'300px', width:'100%'}}>
//                     {/* <div style={{textAlign:'center'}}>
//                         {enterMsg}
//                     </div> */}
//                     <ShowChatList 
//                         receivedMessages={receivedMessages} 
//                         member_id={member_id} 
//                         // user={user}
//                         // enterMsg={enterMsg}
//                     />
//                 </main>
//                 <footer>
//                     <form onSubmit={sendMessage}>
//                         <textarea
//                             type='text'
//                             cols='35'
//                             value={message}
//                             onChange={e => {setMessage(e.target.value)}}
//                         />&nbsp;
//                         <button type='submit'>전송</button>
//                     </form>
//                 </footer>
//             </section>
//             )
//             : 
//             null}
//         </div>
//     );
// };

// export default ModalChat;