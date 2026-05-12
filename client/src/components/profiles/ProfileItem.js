import React from 'react';
import { Link } from 'react-router-dom';
import PropTypes from 'prop-types';

const ProfileItem = ({
  profile: {
    user,
    status,
    company,
    location,
    skills
  }
}) => {
  const _id = user ? user._id : 'unknown';
  const name = user ? user.name : 'Unknown User';
  const avatar = user ? user.avatar : 'https://www.gravatar.com/avatar/?d=mp';

  return (
    <div className='profile-card'>
      <img src={avatar} alt='' className='round-img' />
      <div>
        <h2>{name}</h2>
        <p>
          {status} {company && <span> at {company}</span>}
        </p>
        <p className='my-1'>{location && <span>{location}</span>}</p>
        <Link to={`/profile/${_id}`} className='btn btn-primary'>
          View Profile
        </Link>
      </div>
      <div className='skill-pills'>
        {skills.slice(0, 4).map((skill, index) => (
          <span key={index} className='skill-pill'>
            {skill}
          </span>
        ))}
      </div>
    </div>
  );
};

ProfileItem.propTypes = {
  profile: PropTypes.object.isRequired
};

export default ProfileItem;
