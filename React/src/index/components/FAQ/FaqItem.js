// FaqItem.js
import React from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faChevronDown, faTimes } from '@fortawesome/free-solid-svg-icons';
import parse from 'html-react-parser';

const FaqItem = ({ faq, index, toggleFaq }) => {
  return (
    <div
      key={faq.faq_num}
      className={`faq ${faq.active ? "active" : ""}`}
      onClick={() => toggleFaq(index)}
    >
      <p style={{ color: "grey" }}> {parse(faq.f_type)}</p>
      <h3 className="faq-title">{parse(faq.title)}</h3>
      <p className="faq-text">{parse(faq.content)}</p>
      <button type="button" className="faq-toggle">
        {!faq.active ? 
          <FontAwesomeIcon  icon={faChevronDown} />
          :
          <FontAwesomeIcon  icon={faTimes} />
        }
      </button>
    </div>
  );
}

export default FaqItem;
