import React, { Fragment } from 'react';
import PropTypes from 'prop-types';

const ProfileAbout = ({
  profile: {
    bio,
    skills,
    user
  }
}) => {
  const name = user ? user.name : 'Unknown User';
  return (
    <div className='profile-content-card'>
    {bio && (
      <Fragment>
        <h2 className='text-primary'>{name.trim().split(' ')[0]}s Bio</h2>
        <p>{bio}</p>
        <div className='line' />
      </Fragment>
    )}
    <h2 className='text-primary'>Skill Set</h2>
    <div className='skill-pills'>
      {skills.map((skill, index) => (
        <span key={index} className='skill-pill'>
          {skill}
        </span>
      ))}
    </div>
  </div>
  );
};

ProfileAbout.propTypes = {
  profile: PropTypes.object.isRequired
};

export default ProfileAbout;
